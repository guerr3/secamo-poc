from __future__ import annotations

from datetime import datetime, timezone

from shared.config import QUEUE_EDR
from shared.models.canonical import (
    Correlation,
    DefenderDetectionFindingEvent,
    DefenderSecuritySignalEvent,
    Envelope,
    StoragePartition,
)
from shared.routing.defaults import build_default_route_registry
from workers.run_worker import _validate_route_worker_parity, load_workflows


def _correlation() -> Correlation:
    return Correlation(
        correlation_id="corr-1",
        causation_id="corr-1",
        request_id="req-1",
        trace_id="trace-1",
        storage_partition=StoragePartition(
            ddb_pk="TENANT#tenant-1",
            ddb_sk="EVENT#defender#routing#evt-1",
            s3_bucket="secamo-events-tenant-1",
            s3_key_prefix="raw/defender/evt-1",
        ),
    )


def _signal_envelope(provider_event_type: str) -> Envelope:
    return Envelope(
        event_id=f"evt-{provider_event_type}",
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.security_signal",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=_correlation(),
        payload=DefenderSecuritySignalEvent(
            event_type="defender.security_signal",
            activity_id=2100,
            activity_name="poller.fetch",
            signal_id=f"sig-{provider_event_type}",
            provider_event_type=provider_event_type,
            resource_type=f"resource-{provider_event_type}",
            title=f"Title {provider_event_type}",
            severity_id=40,
            severity="medium",
        ),
    )


def _alert_envelope() -> Envelope:
    return Envelope(
        event_id="evt-alert-1",
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.alert",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=_correlation(),
        payload=DefenderDetectionFindingEvent(
            event_type="defender.alert",
            activity_id=2004,
            alert_id="alert-1",
            title="Alert",
            severity_id=60,
            severity="high",
        ),
    )


def test_signin_log_routes_to_signin_anomaly_detection_workflow() -> None:
    registry = build_default_route_registry()
    routes = registry.resolve(_signal_envelope("signin_log"))

    assert len(routes) == 1
    assert routes[0].workflow_name == "SigninAnomalyDetectionWorkflow"


def test_risky_user_routes_to_risky_user_triage_workflow() -> None:
    registry = build_default_route_registry()
    routes = registry.resolve(_signal_envelope("risky_user"))

    assert len(routes) == 1
    assert routes[0].workflow_name == "RiskyUserTriageWorkflow"


def test_noncompliant_device_routes_to_device_compliance_workflow() -> None:
    registry = build_default_route_registry()
    routes = registry.resolve(_signal_envelope("noncompliant_device"))

    assert len(routes) == 1
    assert routes[0].workflow_name == "DeviceComplianceRemediationWorkflow"


def test_audit_log_routes_to_audit_log_anomaly_workflow() -> None:
    registry = build_default_route_registry()
    routes = registry.resolve(_signal_envelope("audit_log"))

    assert len(routes) == 1
    assert routes[0].workflow_name == "AuditLogAnomalyWorkflow"


def test_unknown_signal_type_falls_back_to_soc_alert_triage() -> None:
    registry = build_default_route_registry()
    routes = registry.resolve(_signal_envelope("unknown_future_signal"))

    assert len(routes) == 1
    assert routes[0].workflow_name == "SocAlertTriageWorkflow"


def test_defender_alert_event_type_still_routes_correctly() -> None:
    registry = build_default_route_registry()
    routes = registry.resolve(_alert_envelope())

    assert len(routes) == 1
    assert routes[0].workflow_name == "SocAlertTriageWorkflow"


def test_all_four_signal_routes_target_queue_edr() -> None:
    registry = build_default_route_registry()

    for provider_event_type in ("signin_log", "risky_user", "noncompliant_device", "audit_log"):
        routes = registry.resolve(_signal_envelope(provider_event_type))
        assert len(routes) == 1
        assert routes[0].task_queue == QUEUE_EDR


def test_route_worker_parity_passes_after_registration() -> None:
    workflows_map = load_workflows()

    _validate_route_worker_parity(workflows_map)
