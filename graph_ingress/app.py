from __future__ import annotations

import asyncio
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

from shared.models import GraphNotificationEnvelope

from .chatops_webhook import router as chatops_router
from .dispatcher import TemporalGraphIngressDispatcher
from .validator import GraphIngressValidator

app = FastAPI(title="Secamo Graph Ingress Service", version="1.0.0")
_validator = GraphIngressValidator()
_dispatcher = TemporalGraphIngressDispatcher()
app.include_router(chatops_router)


@app.get("/graph/notifications", response_class=PlainTextResponse)
async def graph_validation_challenge(validationToken: str | None = None) -> PlainTextResponse:
    """Handle Microsoft Graph endpoint validation challenge."""
    if not validationToken:
        raise HTTPException(status_code=400, detail="Missing validationToken query parameter")
    return PlainTextResponse(content=validationToken, media_type="text/plain")


@app.post("/graph/notifications", response_model=None)
async def receive_graph_notifications(
    request: Request,
    validationToken: str | None = None,
) -> dict:
    """Validate and enqueue Graph change notifications for Temporal routing."""
    if validationToken:
        return PlainTextResponse(content=validationToken, media_type="text/plain")

    payload = await request.json()
    envelope = GraphNotificationEnvelope.model_validate(payload)

    resolved = _validator.validate_and_resolve(envelope)
    if not resolved:
        return {"status": "accepted", "dispatched": 0, "ignored": len(envelope.value)}

    grouped: dict[str, list] = defaultdict(list)
    for item in resolved:
        grouped[item.tenant_id].append(item.item)

    async def _dispatch_all() -> None:
        for tenant_id, notifications in grouped.items():
            await _dispatcher.dispatch(tenant_id=tenant_id, notifications=notifications)

    asyncio.create_task(_dispatch_all())
    return {"status": "accepted", "dispatched": len(resolved), "ignored": len(envelope.value) - len(resolved)}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
