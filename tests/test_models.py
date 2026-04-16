"""Tests for canonical model contracts and ingress mapping behavior."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from shared.ingress.envelope_builder import build_envelope
from shared.ingress.normalization import normalize_event_body
from shared.models import (
    ApprovalDecision,
    Correlation,
    DefenderDetectionFindingEvent,
    Envelope,
    GraphNotificationEnvelope,
    HiTLCaseInput,
    HiTLRequest,
    HitlApprovalEvent,
    IamIngressRequest,
    SecurityCaseInput,
    UserLifecycleCaseInput,
    VendorExtension,
    to_approval_decision,
)
from shared.models.canonical import StoragePartition, derive_event_id
from shared.models.common import LifecycleAction
from shared.routing import resolve_polling_route, resolve_provider_event_route


@pytest.fixture()
def cli_payload() -> dict:
    return {
        "action": "create",
        "user_data": {
            "email": "john.doe@secamo.be",
            "first_name": "John",
            "last_name": "Doe",
            "department": "Engineering",
            "role": "Developer",
            "manager_email": None,
            "license_sku": None,
        },
        "requester": "admin@secamo.be",
        "ticket_id": "TKT-TEST-001",
    }


class TestIngressHandlerMapping:
    def test_defender_alert_mapping_to_envelope(self) -> None:
        raw_body = {
            "request_id": "req-001",
            "correlation_id": "corr-001",
            "timestamp": "2025-01-01T10:00:00Z",
            "alert": {
                "id": "ALT-100",
                "severity": "high",
                "title": "Suspicious login",
                "description": "Multiple failed logins",
                "userPrincipalName": "alice@example.com",
                "ipAddress": "10.0.0.1",
                "destinationIp": "10.0.0.2",
                "deviceId": "device-1",
            },
        }

        normalized = normalize_event_body(
            provider="microsoft_defender",
            event_type="alert",
            tenant_id="tenant-demo-001",
            raw_body=raw_body,
        )
        envelope = build_envelope(
            raw_body=raw_body,
            normalized=normalized,
            provider="microsoft_defender",
            tenant_id="tenant-demo-001",
            event_type=str(normalized.get("event_type") or "alert"),
        )

        assert isinstance(envelope.payload, DefenderDetectionFindingEvent)
        assert envelope.payload.event_type == "defender.alert"
        assert envelope.payload.alert_id == "ALT-100"
        assert envelope.payload.severity_id == 60
        assert envelope.tenant_id == "tenant-demo-001"
        assert envelope.source_provider == "microsoft_defender"
        assert envelope.correlation.correlation_id == "corr-001"
        assert envelope.correlation.request_id == "req-001"
        assert envelope.correlation.storage_partition.ddb_pk == "TENANT#tenant-demo-001"

        expected_event_id = derive_event_id(
            tenant_id="tenant-demo-001",
            event_type="defender.alert",
            occurred_at=datetime(2025, 1, 1, 10, 0, tzinfo=timezone.utc),
            correlation_id="corr-001",
            provider_event_id="ALT-100",
        )
        assert envelope.event_id == expected_event_id

    def test_internal_iam_mapping_to_envelope(self, cli_payload: dict) -> None:
        request = IamIngressRequest.model_validate(cli_payload)
        raw_body = request.model_dump(mode="json")

        normalized = normalize_event_body(
            provider="microsoft_graph",
            event_type="iam_request",
            tenant_id="tenant-demo-001",
            raw_body=raw_body,
        )
        envelope = build_envelope(
            raw_body=raw_body,
            normalized=normalized,
            provider="microsoft_graph",
            tenant_id="tenant-demo-001",
            event_type="iam.onboarding",
        )

        assert envelope.payload.event_type == "iam.onboarding"
        assert envelope.payload.user_email == "john.doe@secamo.be"
        assert envelope.payload.action == LifecycleAction.CREATE
        assert envelope.payload.activity_id == 1
        assert envelope.source_provider == "microsoft_graph"


def test_legacy_model_exports_removed() -> None:
    import shared.models as models

    removed_symbols = (
        "RawIngressEnvelope",
        "ProviderEvent",
        "DefenderWebhook",
        "TeamsApprovalCallback",
        "SignalWorkflowCommand",
        "StartWorkflowCommand",
        "WorkflowCommand",
        "build_provider_event",
        "iam_request_to_envelope",
        "to_envelope",
        "to_workflow_command",
    )
    for symbol in removed_symbols:
        assert not hasattr(models, symbol)


def test_canonical_to_approval_decision() -> None:
    envelope = Envelope(
        event_id="evt-approval-1",
        tenant_id="tenant-demo-001",
        source_provider="teams",
        event_name="hitl.approval",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=Correlation(
            correlation_id="corr-approval-1",
            causation_id="corr-approval-1",
            request_id="req-approval-1",
            trace_id="trace-approval-1",
            storage_partition=StoragePartition(
                ddb_pk="TENANT#tenant-demo-001",
                ddb_sk="EVENT#hitl#approval#evt-approval-1",
                s3_bucket="secamo-events-tenant-demo-001",
                s3_key_prefix="raw/hitl.approval/evt-approval-1",
            ),
        ),
        payload=HitlApprovalEvent(
            event_type="hitl.approval",
            activity_id=990001,
            activity_name="hitl_response",
            approval_id="wf-impossible-travel-001",
            decision="approved",
            channel="teams",
            responder="analyst@secamo.be",
            reason="False positive",
            vendor_extensions={
                "action": VendorExtension(source="teams", value="dismiss"),
            },
        ),
    )

    decision = to_approval_decision(envelope)
    assert isinstance(decision, ApprovalDecision)
    assert decision.approved is True
    assert decision.action == "dismiss"


class TestExtraFieldsIgnored:
    def test_iam_request_ignores_unknown_fields(self):
        data = {
            "action": "create",
            "user_data": {"email": "a@b.com"},
            "requester": "admin",
            "surprise_field": True,
        }
        req = IamIngressRequest.model_validate(data)
        assert req.action == "create"
        assert not hasattr(req, "surprise_field")

    def test_graph_envelope_ignores_unknown(self):
        data = {
            "value": [
                {
                    "subscriptionId": "sub-1",
                    "changeType": "updated",
                    "resource": "security/alerts_v2/123",
                    "extra": "ignored",
                }
            ],
            "futuristic_field": "v2",
        }
        env = GraphNotificationEnvelope.model_validate(data)
        assert len(env.value) == 1
        assert not hasattr(env, "futuristic_field")


class TestRoutingResolution:
    def test_provider_event_route(self):
        route = resolve_provider_event_route("microsoft_defender", "alert")
        assert route == ("SocAlertTriageWorkflow", "edr")

    def test_polling_route_prefers_payload_provider_event_type(self):
        route = resolve_polling_route(
            provider="microsoft_defender",
            resource_type="defender_alerts",
            payload={"provider_event_type": "impossible_travel"},
        )
        assert route == ("SocAlertTriageWorkflow", "edr")


class TestCaseContracts:
    def test_security_case_input_rejects_unknown_case_type(self) -> None:
        with pytest.raises(Exception):
            SecurityCaseInput(
                tenant_id="tenant-001",
                case_type="unknown_case",  # type: ignore[arg-type]
                severity="high",
                alert_id="alert-001",
            )

    def test_security_case_input_defaults_allowed_actions(self) -> None:
        case = SecurityCaseInput(
            tenant_id="tenant-001",
            case_type="defender_alert",
            severity="high",
            alert_id="alert-001",
        )

        assert case.allowed_actions == ["dismiss", "isolate", "disable_user"]

    def test_user_lifecycle_case_input_accepts_expected_values(self) -> None:
        case = UserLifecycleCaseInput(
            tenant_id="tenant-001",
            action="create",
            user_id="user-001",
            user_email="user@example.com",
            requester="admin@example.com",
        )

        assert case.action == "create"
        assert case.user_email == "user@example.com"

    def test_hitl_case_input_wraps_hitl_request(self) -> None:
        hitl_request = HiTLRequest(
            workflow_id="wf-001",
            run_id="",
            tenant_id="tenant-001",
            title="Approval",
            description="Please review",
            allowed_actions=["dismiss"],
            reviewer_email="analyst@example.com",
        )

        case = HiTLCaseInput(
            tenant_id="tenant-001",
            hitl_request=hitl_request,
        )

        assert case.hitl_request.workflow_id == "wf-001"
