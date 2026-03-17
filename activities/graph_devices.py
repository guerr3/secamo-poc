from __future__ import annotations

from urllib.parse import quote

import httpx
from temporalio import activity

from shared.graph_client import get_defender_token
from shared.models import TenantSecrets

DEFENDER_BASE = "https://api.securitycenter.microsoft.com/api"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _handle_http_error(tenant_id: str, provider: str, status: int, action: str) -> None:
    if status in (401, 403):
        raise RuntimeError(f"[{tenant_id}] Auth failed for {provider}: {status}")
    if status == 429:
        raise RuntimeError(f"[{tenant_id}] {provider} rate limited during {action}: {status}")
    if status >= 500:
        raise RuntimeError(f"[{tenant_id}] {provider} server error during {action}: {status}")


@activity.defn
async def graph_isolate_device(tenant_id: str, device_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_isolate_device: {device_id}")
    token = await get_defender_token(secrets)
    payload = {"Comment": "Isolated by Secamo orchestrator", "IsolationType": "Full"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{DEFENDER_BASE}/machines/{quote(device_id)}/isolate",
            headers=_auth_headers(token),
            json=payload,
        )

    if response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_defender", response.status_code, "graph_isolate_device")
    return response.status_code == 201