from __future__ import annotations

from datetime import datetime, timezone

from shared.models.canonical import (
    Correlation,
    DefenderSecuritySignalEvent,
    Envelope,
    IamOnboardingEvent,
    StoragePartition,
)
from shared.routing.contracts import WorkflowRoute
from shared.temporal.dispatcher import _WorkflowRouteDispatcher, workflow_input_for_route


def _correlation() -> Correlation:
    return Correlation(
        correlation_id="corr-1",
        causation_id="corr-1",
        request_id="req-1",
        trace_id="trace-1",
        storage_partition=StoragePartition(
            ddb_pk="TENANT#tenant-1",
            ddb_sk="EVENT#dispatcher#evt-1",
            s3_bucket="secamo-events-tenant-1",
            s3_key_prefix="raw/dispatcher/evt-1",
        ),
    )


def _security_signal_envelope(*, provider_event_type: str) -> Envelope:
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


def _iam_envelope() -> Envelope:
    return Envelope(
        event_id="evt-iam-1",
        tenant_id="tenant-1",
        source_provider="microsoft_graph",
        event_name="iam.onboarding",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=_correlation(),
        payload=IamOnboardingEvent(
            event_type="iam.onboarding",
            activity_id=1,
            user_email="alice@example.com",
            action="create",
            user_data={"user_id": "user-123"},
        ),
        metadata={"requester": "manager@example.com"},
    )


def _route(workflow_name: str) -> WorkflowRoute:
    return WorkflowRoute(workflow_name=workflow_name, task_queue="edr")


def test_signin_anomaly_detection_workflow_input_is_security_case_input() -> None:
    workflow_input = _WorkflowRouteDispatcher._workflow_input_for_route(
        _route("SigninAnomalyDetectionWorkflow"),
        _security_signal_envelope(provider_event_type="signin_log"),
    )

    assert workflow_input["case_type"] == "signin_log"
    assert "event_id" not in workflow_input


def test_risky_user_triage_workflow_input_is_security_case_input() -> None:
    workflow_input = _WorkflowRouteDispatcher._workflow_input_for_route(
        _route("RiskyUserTriageWorkflow"),
        _security_signal_envelope(provider_event_type="risky_user"),
    )

    assert workflow_input["case_type"] == "risky_user"
    assert "event_id" not in workflow_input


def test_device_compliance_workflow_input_is_security_case_input() -> None:
    workflow_input = _WorkflowRouteDispatcher._workflow_input_for_route(
        _route("DeviceComplianceRemediationWorkflow"),
        _security_signal_envelope(provider_event_type="noncompliant_device"),
    )

    assert workflow_input["case_type"] == "noncompliant_device"
    assert "event_id" not in workflow_input


def test_audit_log_anomaly_workflow_input_is_security_case_input() -> None:
    workflow_input = _WorkflowRouteDispatcher._workflow_input_for_route(
        _route("AuditLogAnomalyWorkflow"),
        _security_signal_envelope(provider_event_type="audit_log"),
    )

    assert workflow_input["case_type"] == "audit_log"
    assert "event_id" not in workflow_input


def test_dispatcher_auto_remediate_defaults_to_false() -> None:
    cases = [
        ("SigninAnomalyDetectionWorkflow", "signin_log"),
        ("RiskyUserTriageWorkflow", "risky_user"),
        ("DeviceComplianceRemediationWorkflow", "noncompliant_device"),
        ("AuditLogAnomalyWorkflow", "audit_log"),
    ]

    for workflow_name, provider_event_type in cases:
        workflow_input = _WorkflowRouteDispatcher._workflow_input_for_route(
            _route(workflow_name),
            _security_signal_envelope(provider_event_type=provider_event_type),
        )
        assert workflow_input["auto_remediate"] is False


def test_iam_onboarding_workflow_input_unchanged() -> None:
    workflow_input = _WorkflowRouteDispatcher._workflow_input_for_route(
        _route("IamOnboardingWorkflow"),
        _iam_envelope(),
    )

    assert workflow_input["tenant_id"] == "tenant-1"
    assert workflow_input["action"] == "create"
    assert workflow_input["user_id"] == "user-123"
    assert "event_id" not in workflow_input


def test_unknown_workflow_receives_raw_envelope_dict() -> None:
    workflow_input = _WorkflowRouteDispatcher._workflow_input_for_route(
        _route("SomeUnknownWorkflow"),
        _security_signal_envelope(provider_event_type="signin_log"),
    )

    assert workflow_input["event_id"].startswith("evt-")


def test_shared_helper_can_preserve_envelope_for_unknown_workflows() -> None:
    envelope = _security_signal_envelope(provider_event_type="signin_log")

    workflow_input = workflow_input_for_route(
        _route("SomeUnknownWorkflow"),
        envelope,
        envelope_fallback_as_dict=False,
    )

    assert isinstance(workflow_input, Envelope)
    assert workflow_input.event_id == envelope.event_id
