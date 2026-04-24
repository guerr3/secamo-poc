from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from shared.models import Correlation, DefenderDetectionFindingEvent, DefenderSecuritySignalEvent, Envelope, StoragePartition
from shared.routing.defaults import build_default_route_registry
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


def _build_signal_envelope(
    *,
    provider_event_id: str | None = None,
    signal_id: str = "signal-abc",
    provider_event_type: str = "risky_user",
    resource_type: str = "entra_risky_users",
) -> Envelope:
    """Build an envelope with a DefenderSecuritySignalEvent payload (has signal_id, no alert_id)."""
    metadata = {}
    if provider_event_id is not None:
        metadata["provider_event_id"] = provider_event_id

    return Envelope(
        event_id="wf-signal-event-id",
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.security_signal",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime(2026, 4, 15, tzinfo=timezone.utc),
        correlation=Correlation(
            correlation_id="corr-sig-1",
            causation_id="corr-sig-1",
            request_id="req-sig-1",
            trace_id="trace-sig-1",
            storage_partition=StoragePartition(
                ddb_pk="TENANT#tenant-1",
                ddb_sk="EVENT#defender#security_signal#sig-1",
                s3_bucket="secamo-events-tenant-1",
                s3_key_prefix="raw/defender.security_signal/sig-1",
            ),
        ),
        payload=DefenderSecuritySignalEvent(
            event_type="defender.security_signal",
            activity_id=2100,
            activity_name="poller.fetch",
            signal_id=signal_id,
            provider_event_type=provider_event_type,
            resource_type=resource_type,
            title="Risky user detected",
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


def test_extract_provider_event_id_falls_back_to_signal_id() -> None:
    """When metadata has no provider_event_id and payload has no alert_id, use signal_id."""
    event = _build_signal_envelope(provider_event_id=None, signal_id="risky-user-42")

    assert _extract_provider_event_id(event) == "risky-user-42"


def test_extract_provider_event_id_returns_none_when_no_id_available() -> None:
    """When neither metadata, alert_id, nor signal_id is available, return None."""
    event = _build_signal_envelope(provider_event_id=None, signal_id="")

    assert _extract_provider_event_id(event) is None


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


def test_polling_manager_uses_envelope_rule_resolution() -> None:
    source = Path("workflows/polling_manager.py").read_text(encoding="utf-8")

    assert "_ROUTE_REGISTRY.resolve(event)" in source
    assert "resolve_polling(" not in source


def test_polling_manager_reuses_shared_route_input_shaping() -> None:
    source = Path("workflows/polling_manager.py").read_text(encoding="utf-8")

    assert "workflow_input_for_route(" in source
    assert "envelope_fallback_as_dict=False" in source


def test_polling_manager_supports_graph_subscription_renewal_poll_type() -> None:
    source = Path("workflows/polling_manager.py").read_text(encoding="utf-8")

    assert "POLL_TYPE_GRAPH_SUBSCRIPTION_RENEWAL" in source
    assert "subscription_list" in source
    assert "subscription_renew" in source
    assert "GRAPH_RENEWAL_LOOKAHEAD_HOURS = 48" in source
    assert "GRAPH_RENEWAL_EXPIRATION_HOURS = 72" in source


@pytest.mark.parametrize(
    ("provider_event_type", "workflow_name"),
    [
        ("signin_log", "SigninAnomalyDetectionWorkflow"),
        ("risky_user", "RiskyUserTriageWorkflow"),
        ("noncompliant_device", "DeviceComplianceRemediationWorkflow"),
        ("audit_log", "AuditLogAnomalyWorkflow"),
    ],
)
def test_polling_signal_envelope_routes_via_exact_provider_event_type_predicates(
    provider_event_type: str,
    workflow_name: str,
) -> None:
    registry = build_default_route_registry()
    event = _build_signal_envelope(
        signal_id=f"signal-{provider_event_type}",
        provider_event_type=provider_event_type,
    )

    routes = registry.resolve(event)

    assert len(routes) == 1
    assert routes[0].workflow_name == workflow_name
