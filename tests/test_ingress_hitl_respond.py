from __future__ import annotations

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


class _DynamoStub:
    def __init__(self, attrs: dict) -> None:
        self._attrs = attrs

    def update_item(self, **_kwargs):
        return {"Attributes": self._attrs}


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
    spec = importlib.util.spec_from_file_location("ingress_handler_hitl_module", handler_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["ingress_handler_hitl_module"] = module
    spec.loader.exec_module(module)
    return module


async def test_hitl_respond_signals_child_workflow_id_from_token_record(monkeypatch) -> None:
    module = _load_handler_module()
    monkeypatch.setenv("HITL_TOKEN_TABLE", "hitl-table")

    module._dynamo = _DynamoStub(
        {
            "workflow_id": {"S": "child-hitl-001"},
            "reviewer_email": {"S": "analyst@example.com"},
            "allowed_actions": {"SS": ["dismiss", "isolate"]},
        }
    )
    signal_spy = _SignalSpy()
    monkeypatch.setattr(module.temporal, "signal_workflow", signal_spy)

    event = SimpleNamespace(
        query_params={"token": "tok-1", "action": "dismiss"},
        headers={},
        body={},
        raw_body="",
    )

    result = await module.handle_hitl_respond(event)

    assert result["statusCode"] == 200
    assert len(signal_spy.calls) == 1
    assert signal_spy.calls[0]["workflow_id"] == "child-hitl-001"
    assert signal_spy.calls[0]["workflow_id"] != "parent-wf-001"


async def test_hitl_respond_ignores_matching_callback_workflow_id_and_targets_token_record(monkeypatch) -> None:
    module = _load_handler_module()
    monkeypatch.setenv("HITL_TOKEN_TABLE", "hitl-table")

    module._dynamo = _DynamoStub(
        {
            "workflow_id": {"S": "child-hitl-777"},
            "reviewer_email": {"S": "analyst@example.com"},
            "allowed_actions": {"SS": ["dismiss", "isolate"]},
        }
    )
    signal_spy = _SignalSpy()
    monkeypatch.setattr(module.temporal, "signal_workflow", signal_spy)

    event = SimpleNamespace(
        query_params={
            "token": "tok-2",
            "action": "isolate",
            "workflow_id": "child-hitl-777",
        },
        headers={},
        body={},
        raw_body="",
    )

    result = await module.handle_hitl_respond(event)

    assert result["statusCode"] == 200
    assert len(signal_spy.calls) == 1
    assert signal_spy.calls[0]["workflow_id"] == "child-hitl-777"


async def test_hitl_respond_rejects_callback_workflow_id_mismatch(monkeypatch) -> None:
    module = _load_handler_module()
    monkeypatch.setenv("HITL_TOKEN_TABLE", "hitl-table")

    module._dynamo = _DynamoStub(
        {
            "workflow_id": {"S": "child-hitl-abc"},
            "reviewer_email": {"S": "analyst@example.com"},
            "allowed_actions": {"SS": ["dismiss", "isolate"]},
        }
    )
    signal_spy = _SignalSpy()
    monkeypatch.setattr(module.temporal, "signal_workflow", signal_spy)

    event = SimpleNamespace(
        query_params={
            "token": "tok-3",
            "action": "dismiss",
            "workflow_id": "parent-wf-xyz",
        },
        headers={},
        body={},
        raw_body="",
    )

    result = await module.handle_hitl_respond(event)

    assert result["statusCode"] == 403
    assert "Workflow identity mismatch" in result["body"]
    assert signal_spy.calls == []


async def test_hitl_respond_post_teams_payload_uses_token_workflow_target(monkeypatch) -> None:
    module = _load_handler_module()
    monkeypatch.setenv("HITL_TOKEN_TABLE", "hitl-table")

    module._dynamo = _DynamoStub(
        {
            "workflow_id": {"S": "child-hitl-post-001"},
            "reviewer_email": {"S": "analyst@example.com"},
            "allowed_actions": {"SS": ["dismiss", "isolate"]},
        }
    )
    signal_spy = _SignalSpy()
    monkeypatch.setattr(module.temporal, "signal_workflow", signal_spy)

    event = SimpleNamespace(
        query_params={},
        headers={"content-type": "application/json"},
        body={
            "token": "tok-post-1",
            "action": "isolate",
            "workflow_id": "child-hitl-post-001",
            "actor": "teams:29:1",
            "comments": "Approved from Teams card",
        },
        raw_body="{}",
    )

    result = await module.handle_hitl_respond(event)

    assert result["statusCode"] == 200
    assert len(signal_spy.calls) == 1
    assert signal_spy.calls[0]["workflow_id"] == "child-hitl-post-001"
    assert signal_spy.calls[0]["payload"]["reviewer"] == "teams:29:1"
    assert signal_spy.calls[0]["payload"]["comments"] == "Approved from Teams card"


async def test_hitl_respond_post_teams_payload_rejects_mismatched_workflow_id(monkeypatch) -> None:
    module = _load_handler_module()
    monkeypatch.setenv("HITL_TOKEN_TABLE", "hitl-table")

    module._dynamo = _DynamoStub(
        {
            "workflow_id": {"S": "child-hitl-post-abc"},
            "reviewer_email": {"S": "analyst@example.com"},
            "allowed_actions": {"SS": ["dismiss", "isolate"]},
        }
    )
    signal_spy = _SignalSpy()
    monkeypatch.setattr(module.temporal, "signal_workflow", signal_spy)

    event = SimpleNamespace(
        query_params={},
        headers={"content-type": "application/json"},
        body={
            "token": "tok-post-2",
            "action": "dismiss",
            "workflow_id": "parent-wf-wrong",
            "actor": "teams:29:2",
        },
        raw_body="{}",
    )

    result = await module.handle_hitl_respond(event)

    assert result["statusCode"] == 403
    assert "Workflow identity mismatch" in result["body"]
    assert signal_spy.calls == []
