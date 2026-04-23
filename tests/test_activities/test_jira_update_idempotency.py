"""Jira update_issue idempotency tests for HiTL threaded dispatch.

Validates that the idempotency key is deterministic across retries and that
duplicate comment posting is guarded by the connector's marker check.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import activities.hitl as hitl_module
from shared.models import HitlCallbackBinding, HiTLRequest


def _sample_request_with_ticket_key() -> HiTLRequest:
    return HiTLRequest(
        workflow_id="parent-wf-001",
        run_id="run-001",
        tenant_id="tenant-001",
        title="Approve containment",
        description="Suspicious sign-in requires approval",
        allowed_actions=["dismiss", "isolate"],
        reviewer_email="reviewer@example.com",
        channels=["jira"],
        ticket_key="SEC-42",
        metadata={"severity": "high"},
    )


def _sample_binding() -> HitlCallbackBinding:
    return HitlCallbackBinding(
        token="tok-idem-001",
        callback_endpoint="https://example.com/api/v1/hitl/respond",
        workflow_id="parent-wf-001",
        run_id="run-001",
        allowed_actions=("dismiss", "isolate"),
    )


@pytest.mark.asyncio
async def test_jira_update_idempotency_key_is_deterministic_across_calls(monkeypatch) -> None:
    """Two calls with the same request + binding must produce the same comment_idempotency_key."""
    request = _sample_request_with_ticket_key()
    binding = _sample_binding()

    captured_keys: list[str] = []

    async def _fake_connector_execute_action(_tenant_id, _provider, _action, payload):
        captured_keys.append(payload.get("comment_idempotency_key", ""))
        return SimpleNamespace(data=SimpleNamespace(payload={"issueKey": "SEC-42"}))

    async def _tenant_cfg(_tenant_id):
        return SimpleNamespace(ticketing_provider="jira")

    monkeypatch.setattr(hitl_module, "get_tenant_config", _tenant_cfg)
    monkeypatch.setattr(hitl_module, "connector_execute_action", _fake_connector_execute_action)

    await hitl_module._dispatch_jira(request, binding)
    await hitl_module._dispatch_jira(request, binding)

    assert len(captured_keys) == 2
    assert captured_keys[0] == captured_keys[1], (
        "Idempotency key must be identical across retries"
    )
    assert len(captured_keys[0]) == 64, (
        "Idempotency key must be a 64-char SHA-256 hex digest"
    )


@pytest.mark.asyncio
async def test_jira_update_uses_update_issue_action_when_ticket_key_present(monkeypatch) -> None:
    """When ticket_key is set, the Jira dispatch must use update_issue, not create_ticket."""
    request = _sample_request_with_ticket_key()
    binding = _sample_binding()

    captured: dict = {}

    async def _fake_connector_execute_action(tenant_id, provider, action, payload):
        captured["action"] = action
        captured["payload"] = payload
        return SimpleNamespace(data=SimpleNamespace(payload={"issueKey": "SEC-42"}))

    async def _tenant_cfg(_tenant_id):
        return SimpleNamespace(ticketing_provider="jira")

    monkeypatch.setattr(hitl_module, "get_tenant_config", _tenant_cfg)
    monkeypatch.setattr(hitl_module, "connector_execute_action", _fake_connector_execute_action)

    result = await hitl_module._dispatch_jira(request, binding)

    assert result.success is True
    assert result.message_id == "SEC-42"
    assert captured["action"] == "update_issue"
    assert captured["payload"]["ticket_id"] == "SEC-42"
    assert "comment" in captured["payload"]
    assert "comment_idempotency_key" in captured["payload"]
