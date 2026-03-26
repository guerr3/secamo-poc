"""Phase-3 verification for signal and envelope contracts.

Responsibility: validate discriminated unions, immutable envelope models, and signal gateway mapping.
This module must not test provider normalizers or route registries.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import TypeAdapter, ValidationError

from shared.approval.contracts import ApprovalSignal, SignalPayload
from shared.models.canonical import Correlation, DefenderDetectionFindingEvent, Envelope, StoragePartition
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


def test_envelope_is_frozen() -> None:
    envelope = Envelope(
        event_id="evt-1",
        tenant_id="tenant-1",
        source_provider="jira",
        event_name="defender.alert",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=Correlation(
            correlation_id="corr-1",
            causation_id="corr-1",
            request_id="req-1",
            trace_id="trace-1",
            storage_partition=StoragePartition(
                ddb_pk="TENANT#tenant-1",
                ddb_sk="EVENT#defender#alert#evt-1",
                s3_bucket="secamo-events-tenant-1",
                s3_key_prefix="raw/defender.alert/evt-1",
            ),
        ),
        payload=DefenderDetectionFindingEvent(
            event_type="defender.alert",
            activity_id=2004,
            alert_id="a-1",
            title="Test alert",
            severity_id=60,
        ),
    )

    with pytest.raises(ValidationError):
        envelope.tenant_id = "tenant-2"


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
