from __future__ import annotations

import hashlib
import hmac
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace


class _SignalSpy:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return {}


class _SsmStub:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def get_parameter(self, **_kwargs):
        return {"Parameter": {"Value": self.secret}}


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
    spec = importlib.util.spec_from_file_location("ingress_handler_core_module", handler_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["ingress_handler_core_module"] = module
    spec.loader.exec_module(module)
    return module


async def test_handle_event_dispatches_provider_event(monkeypatch) -> None:
    module = _load_handler_module()

    class _FakePipeline:
        async def dispatch_provider_event(
            self,
            *,
            raw_body,
            provider,
            event_type,
            tenant_id,
            headers,
            raw_body_text,
            channel,
            authenticate,
        ):
            assert raw_body["provider"] == "DEFENDER"
            assert provider == "defender"
            assert event_type == "alert"
            assert tenant_id == "tenant-demo-001"
            assert headers["x-id"] == "42"
            assert raw_body_text == '{"provider":"DEFENDER","event_type":"alert"}'
            assert channel == "webhook"
            assert authenticate is True
            return SimpleNamespace(
                accepted=True,
                status_code=202,
                tenant_id=tenant_id,
                provider=provider,
                event_type=event_type,
                attempted=1,
                succeeded=1,
                failed=0,
            )

    monkeypatch.setattr(module, "_get_ingress_pipeline", lambda: _FakePipeline())

    event = SimpleNamespace(
        tenant_id="tenant-demo-001",
        headers={"x-id": 42},
        body={"provider": "DEFENDER", "event_type": "alert"},
        raw_body='{"provider":"DEFENDER","event_type":"alert"}',
    )

    result = await module.handle_event(event)

    assert result["statusCode"] == 202
    assert result["body"]["provider"] == "defender"
    assert result["body"]["succeeded"] == 1


async def test_handle_internal_dispatches_iam_request(monkeypatch) -> None:
    module = _load_handler_module()

    class _FakePipeline:
        async def dispatch_provider_event(
            self,
            *,
            raw_body,
            provider,
            event_type,
            tenant_id,
            authenticate,
            **_kwargs,
        ):
            assert provider == "microsoft_graph"
            assert event_type == "iam_request"
            assert tenant_id == "tenant-demo-002"
            assert authenticate is False
            assert raw_body["action"] == "create"
            assert raw_body["requester"] == "manager@example.com"
            return SimpleNamespace(
                accepted=True,
                status_code=202,
                tenant_id=tenant_id,
                provider=provider,
                event_type=event_type,
                attempted=1,
                succeeded=1,
                failed=0,
            )

    monkeypatch.setattr(module, "_get_ingress_pipeline", lambda: _FakePipeline())

    event = SimpleNamespace(
        tenant_id="tenant-demo-002",
        body={
            "action": "create",
            "user_data": {
                "employee_email": "jane@example.com",
                "display_name": "Jane Doe",
            },
            "requester": "manager@example.com",
            "ticket_id": "IAM-42",
        },
    )

    result = await module.handle_internal(event)

    assert result["statusCode"] == 202
    assert result["body"]["event_type"] == "iam_request"
    assert result["body"]["succeeded"] == 1


async def test_handle_hitl_jira_validates_signature_and_signals(monkeypatch) -> None:
    module = _load_handler_module()

    shared_secret = "jira-hitl-secret"
    raw_body = "{}"
    signature = "sha256=" + hmac.new(
        shared_secret.encode("utf-8"),
        raw_body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    module._ssm = _SsmStub(shared_secret)
    signal_spy = _SignalSpy()
    monkeypatch.setattr(module.temporal, "signal_workflow", signal_spy)

    event = SimpleNamespace(
        tenant_id="tenant-demo-003",
        headers={"x-hub-signature-256": signature},
        body={
            "issue": {
                "key": "SOC-9",
                "fields": {
                    "status": {"name": "Approved"},
                    "labels": ["secamo-wf:wf-hitl-123"],
                },
            },
            "comment": {
                "comments": [
                    {"body": "isolate"},
                ]
            },
        },
        raw_body=raw_body,
    )

    result = await module.handle_hitl_jira(event)

    assert result["statusCode"] == 200
    assert result["body"]["signaled"] == "wf-hitl-123"
    assert len(signal_spy.calls) == 1
    assert signal_spy.calls[0]["workflow_id"] == "wf-hitl-123"
    assert signal_spy.calls[0]["signal"] == "approve"
    assert signal_spy.calls[0]["payload"]["approved"] is True
    assert signal_spy.calls[0]["payload"]["action"] == "isolate"