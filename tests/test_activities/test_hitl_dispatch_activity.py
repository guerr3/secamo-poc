from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

import activities.hitl as hitl_module
from shared.models import (
    HitlCallbackBinding,
    HitlChannelDispatchResult,
    HiTLRequest,
    TenantSecrets,
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


def _sample_graph_secrets() -> TenantSecrets:
    return TenantSecrets(
        client_id="cid",
        client_secret="secret",
        tenant_azure_id="azure-tenant",
    )


@pytest.mark.asyncio
async def test_request_hitl_approval_returns_typed_results_for_supported_and_unsupported_channels(
    monkeypatch,
) -> None:
    request = _sample_request(["email", "teams", "jira"])
    graph_secrets = _sample_graph_secrets()

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

    async def _email_ok(_request, _secrets, _binding):
        return HitlChannelDispatchResult(channel="email", success=True, message_id="mail-1")

    async def _teams_ok(_request, _binding):
        return HitlChannelDispatchResult(channel="teams", success=True, message_id="teams-1")

    monkeypatch.setattr(hitl_module, "_dispatch_email", _email_ok)
    monkeypatch.setattr(hitl_module, "_dispatch_teams", _teams_ok)

    result = await hitl_module.request_hitl_approval("tenant-001", request, graph_secrets, None)

    assert result.workflow_id == "child-hitl-123"
    assert result.run_id == "child-run-123"
    assert result.any_channel_succeeded is True
    assert [item.channel for item in result.channel_results] == ["email", "teams", "jira"]
    assert result.channel_results[0].success is True
    assert result.channel_results[1].success is True
    assert result.channel_results[2].success is False
    assert result.channel_results[2].error_type == "UnsupportedChannel"
    assert result.failed_channels == ["jira"]


@pytest.mark.asyncio
async def test_request_hitl_approval_raises_when_all_channels_fail(monkeypatch) -> None:
    request = _sample_request(["jira"])
    graph_secrets = _sample_graph_secrets()

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

    with pytest.raises(ApplicationError) as exc:
        await hitl_module.request_hitl_approval("tenant-001", request, graph_secrets, None)

    assert exc.value.type == "HiTLDispatchFailed"
