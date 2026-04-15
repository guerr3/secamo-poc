from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from shared.models import Correlation, DefenderDetectionFindingEvent, Envelope, StoragePartition
from workflows.polling_manager import _child_workflow_id, _extract_provider_event_id


def _build_envelope(*, provider_event_id: str | None = None) -> Envelope:
    metadata = {}
    if provider_event_id is not None:
        metadata["provider_event_id"] = provider_event_id

    return Envelope(
        event_id="wf-event-id",
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.alert",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime(2026, 4, 15, tzinfo=timezone.utc),
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
            alert_id="alert-fallback-1",
            title="Alert",
            severity_id=60,
            severity="high",
        ),
        metadata=metadata,
    )


def test_extract_provider_event_id_prefers_metadata() -> None:
    event = _build_envelope(provider_event_id="alert-meta-1")

    assert _extract_provider_event_id(event) == "alert-meta-1"


def test_extract_provider_event_id_falls_back_to_alert_id() -> None:
    event = _build_envelope(provider_event_id=None)

    assert _extract_provider_event_id(event) == "alert-fallback-1"


def test_child_workflow_id_sanitizes_event_identifier() -> None:
    workflow_id = _child_workflow_id(
        provider="microsoft_defender",
        resource_type="defender_alerts",
        tenant_id="tenant-1",
        dedup_event_id="alert/with #spaces",
    )

    assert workflow_id == "microsoft_defender-defender_alerts-tenant-1-alert_with__spaces"


def test_polling_manager_refreshes_config_each_iteration() -> None:
    source = Path("workflows/polling_manager.py").read_text(encoding="utf-8")

    assert "get_tenant_config" in source
    assert "if input.iteration == 0" not in source
