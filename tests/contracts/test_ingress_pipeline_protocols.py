"""Phase-1 verification for ingress pipeline protocol contracts.

Responsibility: validate protocol conformance and frozen-model behavior for contract modules.
This test module must not validate provider-specific logic or Temporal dispatch behavior.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from shared.ingress.contracts import (
    AuthResult,
    DispatchItem,
    DispatchPlan,
    DispatchResult,
    IngressContext,
    IngressRequest,
    IngressSignal,
)
from shared.ingress.pipeline import AuthenticateStage, DispatchStage, NormalizeStage, RouteStage


class StubAuthenticate:
    async def __call__(self, request: IngressRequest, context: IngressContext) -> AuthResult:
        return AuthResult(authenticated=True, principal=f"tenant:{request.tenant_id}")


class StubNormalize:
    async def __call__(
        self,
        request: IngressRequest,
        context: IngressContext,
        auth: AuthResult,
    ) -> IngressSignal:
        return IngressSignal(
            intent_name="ingress.event",
            payload={"event_type": request.event_type},
            attributes={"principal": auth.principal or "unknown"},
        )


class StubRoute:
    async def __call__(
        self,
        signal: IngressSignal,
        request: IngressRequest,
        context: IngressContext,
    ) -> DispatchPlan:
        item = DispatchItem(
            workflow_name="ExampleWorkflow",
            task_queue="example-queue",
            signal=signal,
        )
        return DispatchPlan(
            provider=request.provider,
            event_type=request.event_type,
            tenant_id=request.tenant_id,
            items=(item,),
        )


class StubDispatch:
    async def __call__(self, plan: DispatchPlan, context: IngressContext) -> DispatchResult:
        return DispatchResult(dispatched_count=len(plan.items), failed_count=0)


@pytest.mark.asyncio
async def test_pipeline_protocol_stubs_conform() -> None:
    request = IngressRequest(tenant_id="tenant-1", provider="provider-x", event_type="event-y")
    context = IngressContext(surface="lambda", received_at=datetime.now(timezone.utc))

    authenticate = StubAuthenticate()
    normalize = StubNormalize()
    route = StubRoute()
    dispatch = StubDispatch()

    assert isinstance(authenticate, AuthenticateStage)
    assert isinstance(normalize, NormalizeStage)
    assert isinstance(route, RouteStage)
    assert isinstance(dispatch, DispatchStage)

    auth = await authenticate(request, context)
    signal = await normalize(request, context, auth)
    plan = await route(signal, request, context)
    result = await dispatch(plan, context)

    assert auth.authenticated is True
    assert signal.intent_name == "ingress.event"
    assert len(plan.items) == 1
    assert result.dispatched_count == 1


def test_ingress_contract_models_are_mutable_for_poc_scope() -> None:
    request = IngressRequest(tenant_id="tenant-1", provider="provider-x", event_type="event-y")
    request.tenant_id = "tenant-2"
    assert request.tenant_id == "tenant-2"
