from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

from shared.auth.contracts import AuthValidationResult
from shared.ingress.pipeline import IngressPipeline


def _load_handler_module():
    ingress_sdk = types.ModuleType("ingress_sdk")
    temporal_module = types.ModuleType("ingress_sdk.temporal")
    response_module = types.ModuleType("ingress_sdk.response")
    dispatch_module = types.ModuleType("ingress_sdk.dispatch")
    event_module = types.ModuleType("ingress_sdk.event")

    async def _not_used(*_args, **_kwargs):
        return {}

    temporal_module.start_workflow = _not_used
    temporal_module.signal_workflow = _not_used

    response_module.error = lambda code, message: {"statusCode": code, "body": message}
    response_module.accepted = lambda body: {"statusCode": 202, "body": body}
    response_module.ok = lambda body: {"statusCode": 200, "body": body}

    dispatch_module.async_handler = lambda routes: routes
    event_module.IngressEvent = object

    ingress_sdk.temporal = temporal_module
    ingress_sdk.response = response_module

    sys.modules["ingress_sdk"] = ingress_sdk
    sys.modules["ingress_sdk.temporal"] = temporal_module
    sys.modules["ingress_sdk.response"] = response_module
    sys.modules["ingress_sdk.dispatch"] = dispatch_module
    sys.modules["ingress_sdk.event"] = event_module

    ingress_src = Path("terraform/modules/ingress/src/ingress")
    if str(ingress_src) not in sys.path:
        sys.path.insert(0, str(ingress_src))

    handler_path = ingress_src / "handler.py"
    spec = importlib.util.spec_from_file_location("ingress_handler_module", handler_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["ingress_handler_module"] = module
    spec.loader.exec_module(module)
    return module


async def test_handle_graph_notification_returns_validation_token() -> None:
    module = _load_handler_module()

    event = SimpleNamespace(
        tenant_id="tenant-demo-001",
        path_params={"tenant_id": "tenant-demo-001"},
        query_params={"validationToken": "opaque-token-123"},
        headers={},
        body={},
        raw_body="",
    )

    result = await module.handle_graph_notification(event)

    assert result["statusCode"] == 200
    assert result["body"] == "opaque-token-123"
    assert result["headers"]["Content-Type"] == "text/plain"


async def test_handle_graph_notification_dispatches_supported_items(monkeypatch) -> None:
    module = _load_handler_module()

    class _FakePipeline:
        async def dispatch_graph_notifications(self, *, tenant_id, body, headers, raw_body_text):
            assert tenant_id == "tenant-demo-001"
            assert isinstance(body, dict)
            assert isinstance(headers, dict)
            assert isinstance(raw_body_text, str)
            return SimpleNamespace(
                accepted=True,
                status_code=202,
                received=2,
                dispatched=1,
                ignored=1,
            )

    monkeypatch.setattr(module, "_get_ingress_pipeline", lambda: _FakePipeline())

    event = SimpleNamespace(
        tenant_id="tenant-demo-001",
        path_params={"tenant_id": "tenant-demo-001"},
        query_params={},
        headers={"authorization": "Bearer test"},
        body={
            "value": [
                {
                    "subscriptionId": "sub-1",
                    "changeType": "created",
                    "resource": "security/alerts_v2/123",
                    "clientState": "secamo:tenant-demo-001:alerts",
                    "resourceData": {
                        "id": "alert-123",
                        "severity": "high",
                        "title": "Suspicious sign-in",
                        "userPrincipalName": "analyst@example.com",
                        "ipAddress": "10.0.0.5",
                    },
                },
                {
                    "subscriptionId": "sub-2",
                    "changeType": "created",
                    "resource": "users/abc",
                    "clientState": "secamo:tenant-demo-001:alerts",
                    "resourceData": {"id": "unknown"},
                },
            ]
        },
        raw_body="{}",
    )

    result = await module.handle_graph_notification(event)

    assert result["statusCode"] == 202
    assert result["body"]["received"] == 2
    assert result["body"]["dispatched"] == 1
    assert result["body"]["ignored"] == 1


async def test_dispatch_provider_event_uses_canonical_event_type_for_jira(monkeypatch) -> None:
    captured: dict[str, str] = {}

    class _StubAuthRegistry:
        async def validate(self, _request):
            return AuthValidationResult(authenticated=True, validator_name="stub")

    class _StubGraphHelper:
        def validate_graph_validation_tokens(self, _tokens):
            return True

        def graph_client_state_matches_tenant(self, _client_state, _tenant_id):
            return True

        def graph_event_type_from_resource(self, _resource):
            return ""

        def graph_item_to_provider_payload(self, _item, _event_type):
            return {}

    class _StubDispatcher:
        async def dispatch_intent(self, envelope):
            captured["payload_event_type"] = envelope.payload.event_type
            captured["source_provider"] = envelope.source_provider
            return SimpleNamespace(attempted=1, succeeded=1, failed=0)

    pipeline = IngressPipeline(
        auth_registry=_StubAuthRegistry(),
        route_fanout_dispatcher=_StubDispatcher(),
        graph_helper=_StubGraphHelper(),
    )

    result = await pipeline.dispatch_provider_event(
        raw_body={
            "provider": "jira",
            "event_type": "jira:issue_created",
            "issue": {
                "key": "IAM-42",
                "fields": {
                    "customfield_employee_email": "jane@example.com",
                    "customfield_employee_name": "Jane Doe",
                    "customfield_lifecycle_action": "create",
                    "reporter": {"emailAddress": "manager@example.com"},
                },
            },
        },
        provider="jira",
        event_type="jira:issue_created",
        tenant_id="tenant-demo-001",
        authenticate=False,
    )

    assert result.accepted is True
    assert result.status_code == 202
    assert captured["payload_event_type"] == "iam.onboarding"
    assert captured["source_provider"] == "jira"
