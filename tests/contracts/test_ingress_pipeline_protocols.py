"""Shared ingress pipeline runtime behavior checks.

Responsibility: verify concrete pipeline auth and dispatch orchestration wiring.
This module must not test workflow internals.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shared.auth.contracts import AuthValidationRequest, AuthValidationResult
from shared.ingress.pipeline import AuthResult, IngressPipeline


class _StubAuthRegistry:
    def __init__(self, authenticated: bool = True) -> None:
        self.authenticated = authenticated
        self.last_request: AuthValidationRequest | None = None

    async def validate(self, request: AuthValidationRequest) -> AuthValidationResult:
        self.last_request = request
        return AuthValidationResult(
            authenticated=self.authenticated,
            validator_name="stub",
            principal="principal-1" if self.authenticated else None,
            reason=None if self.authenticated else "signature_mismatch",
        )


class _StubDispatcher:
    def __init__(self) -> None:
        self.last_envelope = None

    async def dispatch_intent(self, envelope):
        self.last_envelope = envelope
        return SimpleNamespace(attempted=1, succeeded=1, failed=0)


class _StubGraphHelper:
    def validate_graph_validation_tokens(self, _tokens):
        return True

    def graph_client_state_matches_tenant(self, _client_state, _tenant_id):
        return True

    def graph_event_type_from_resource(self, _resource):
        return ""

    def graph_item_to_provider_payload(self, _item, _event_type):
        return {}


@pytest.mark.asyncio
async def test_authenticate_calls_registry_validate_directly() -> None:
    registry = _StubAuthRegistry(authenticated=True)
    pipeline = IngressPipeline(
        auth_registry=registry,
        route_fanout_dispatcher=_StubDispatcher(),
        graph_helper=_StubGraphHelper(),
    )

    result = await pipeline.authenticate(
        tenant_id="tenant-1",
        provider="microsoft_defender",
        headers={"x-cs-signature": "abc"},
        raw_body="{}",
        channel="webhook",
    )

    assert isinstance(result, AuthResult)
    assert result.authenticated is True
    assert result.principal == "principal-1"
    assert registry.last_request is not None
    assert registry.last_request.tenant_id == "tenant-1"
    assert registry.last_request.provider == "microsoft_defender"


@pytest.mark.asyncio
async def test_dispatch_provider_event_builds_envelope_and_fanout() -> None:
    dispatcher = _StubDispatcher()
    pipeline = IngressPipeline(
        auth_registry=_StubAuthRegistry(authenticated=True),
        route_fanout_dispatcher=dispatcher,
        graph_helper=_StubGraphHelper(),
    )

    result = await pipeline.dispatch_provider_event(
        raw_body={
            "id": "md-001",
            "severity": "high",
            "title": "Impossible travel",
            "description": "Suspicious sign-in",
            "deviceId": "dev-1",
            "userPrincipalName": "alice@example.com",
            "ipAddress": "10.1.1.2",
        },
        provider="microsoft_defender",
        event_type="alert",
        tenant_id="tenant-demo-001",
        authenticate=False,
    )

    assert result.accepted is True
    assert result.status_code == 202
    assert result.canonical_event_type == "defender.alert"
    assert result.attempted == 1
    assert dispatcher.last_envelope is not None
    assert dispatcher.last_envelope.tenant_id == "tenant-demo-001"
    assert dispatcher.last_envelope.payload.event_type == "defender.alert"
