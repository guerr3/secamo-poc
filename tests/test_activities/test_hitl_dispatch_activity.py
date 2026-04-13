from __future__ import annotations

from types import SimpleNamespace

import pytest
from temporalio.exceptions import ApplicationError

import activities.hitl as hitl_module
from shared.models import (
    HitlCallbackBinding,
    HitlChannelDispatchResult,
    HiTLRequest,
)


def _sample_request(channels: list[str]) -> HiTLRequest:
    return HiTLRequest(
        workflow_id="child-hitl-123",
        run_id="child-run-123",
        tenant_id="tenant-001",
        title="Approve containment",
        description="Suspicious sign-in requires approval",
        allowed_actions=["dismiss", "isolate"],
        reviewer_email="reviewer@example.com",
        channels=channels,
    )


@pytest.mark.asyncio
async def test_request_hitl_approval_returns_typed_results_for_supported_and_unsupported_channels(
    monkeypatch,
) -> None:
    request = _sample_request(["email", "teams", "jira"])

    monkeypatch.setattr(hitl_module.activity, "heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        hitl_module,
        "_build_callback_binding",
        lambda _request: HitlCallbackBinding(
            token="tok-123456789",
            callback_endpoint="https://example.com/api/v1/hitl/respond",
            workflow_id="child-hitl-123",
            run_id="child-run-123",
            allowed_actions=("dismiss", "isolate"),
        ),
    )

    async def _email_ok(_request, _binding):
        return HitlChannelDispatchResult(channel="email", success=True, message_id="mail-1")

    async def _teams_ok(_request, _binding):
        return HitlChannelDispatchResult(channel="teams", success=True, message_id="teams-1")

    async def _jira_ok(_request, _binding):
        return HitlChannelDispatchResult(channel="jira", success=True, message_id="HELP-1")

    monkeypatch.setattr(hitl_module, "_dispatch_email", _email_ok)
    monkeypatch.setattr(hitl_module, "_dispatch_teams", _teams_ok)
    monkeypatch.setattr(hitl_module, "_dispatch_jira", _jira_ok)

    result = await hitl_module.request_hitl_approval("tenant-001", request)

    assert result.workflow_id == "child-hitl-123"
    assert result.run_id == "child-run-123"
    assert result.any_channel_succeeded is True
    assert [item.channel for item in result.channel_results] == ["email", "teams", "jira"]
    assert result.channel_results[0].success is True
    assert result.channel_results[1].success is True
    assert result.channel_results[2].success is True
    assert result.channel_results[2].message_id == "HELP-1"
    assert result.failed_channels == []


@pytest.mark.asyncio
async def test_request_hitl_approval_raises_when_all_channels_fail(monkeypatch) -> None:
    request = _sample_request(["jira"])

    monkeypatch.setattr(hitl_module.activity, "heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        hitl_module,
        "_build_callback_binding",
        lambda _request: HitlCallbackBinding(
            token="tok-123456789",
            callback_endpoint="https://example.com/api/v1/hitl/respond",
            workflow_id="child-hitl-123",
            run_id="child-run-123",
            allowed_actions=("dismiss", "isolate"),
        ),
    )
    async def _jira_fail(_request, _binding):
        return HitlChannelDispatchResult(
            channel="jira",
            success=False,
            error_type="DispatchError",
            error_message="jira unavailable",
        )

    monkeypatch.setattr(hitl_module, "_dispatch_jira", _jira_fail)

    with pytest.raises(ApplicationError) as exc:
        await hitl_module.request_hitl_approval("tenant-001", request)

    assert exc.value.type == "HiTLDispatchFailed"


@pytest.mark.asyncio
async def test_dispatch_jira_creates_ticket_with_workflow_labels(monkeypatch) -> None:
    request = _sample_request(["jira"])
    request = request.model_copy(update={"ticket_key": "SEC-5", "metadata": {"severity": "high"}})
    binding = HitlCallbackBinding(
        token="tok-123456789",
        callback_endpoint="https://example.com/api/v1/hitl/respond",
        workflow_id="child-hitl-123",
        run_id="child-run-123",
        allowed_actions=("dismiss", "isolate"),
    )

    captured: dict = {}

    async def _fake_connector_execute_action(tenant_id, provider, action, payload):
        captured["tenant_id"] = tenant_id
        captured["provider"] = provider
        captured["action"] = action
        captured["payload"] = payload
        return SimpleNamespace(data=SimpleNamespace(payload={"issueKey": "HELP-101"}))

    monkeypatch.setattr(hitl_module, "connector_execute_action", _fake_connector_execute_action)

    result = await hitl_module._dispatch_jira(request, binding)

    assert result.success is True
    assert result.message_id == "HELP-101"
    assert captured["provider"] == "jira"
    assert captured["action"] == "create_ticket"
    assert "secamo-wf:child-hitl-123" in captured["payload"]["labels"]
    assert "secamo-run:child-run-123" in captured["payload"]["labels"]
    assert "secamo-parent:SEC-5" in captured["payload"]["labels"]
