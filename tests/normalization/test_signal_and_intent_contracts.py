"""Phase-3 verification for signal and intent contracts.

Responsibility: validate discriminated unions, immutable intent models, and signal gateway mapping.
This module must not test provider normalizers or route registries.
"""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from shared.approval.contracts import ApprovalSignal, SignalPayload
from shared.normalization.contracts import WorkflowIntent
from shared.temporal.signal_gateway import SignalGateway


class _CaptureTransport:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def send(self, workflow_id: str, run_id: str | None, signal_name: str, payload: dict) -> None:
        self.calls.append(
            {
                "workflow_id": workflow_id,
                "run_id": run_id,
                "signal_name": signal_name,
                "payload": payload,
            }
        )


def test_signal_union_discriminates_approval_payload() -> None:
    adapter = TypeAdapter(SignalPayload)
    parsed = adapter.validate_python(
        {
            "signal_type": "approval",
            "approved": True,
            "actor": "analyst@example.com",
            "comments": "looks good",
        }
    )

    assert isinstance(parsed, ApprovalSignal)
    assert parsed.action == "approve"


def test_signal_union_rejects_unknown_discriminator() -> None:
    adapter = TypeAdapter(SignalPayload)

    with pytest.raises(ValidationError):
        adapter.validate_python({"signal_type": "unknown", "actor": "a"})


def test_workflow_intent_is_frozen() -> None:
    intent = WorkflowIntent(
        tenant_id="tenant-1",
        provider="jira",
        event_type="issue_created",
        intent_type="ingress.alert",
    )

    with pytest.raises(ValidationError):
        intent.provider = "crowdstrike"


@pytest.mark.asyncio
async def test_signal_gateway_dispatches_expected_signal_name() -> None:
    transport = _CaptureTransport()
    gateway = SignalGateway(transport)
    payload = ApprovalSignal(
        approved=True,
        action="approve",
        actor="reviewer@example.com",
        comments="approved",
    )

    await gateway.dispatch(workflow_id="wf-1", run_id="run-1", payload=payload)

    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["signal_name"] == "approve"
    assert call["payload"]["actor"] == "reviewer@example.com"
    assert call["payload"]["action"] == "approve"
    assert call["payload"]["comments"] == "approved"
