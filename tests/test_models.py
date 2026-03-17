"""Tests for shared model mapping into universal SecurityEvent workflow input."""

from datetime import datetime, timezone

import pytest

from shared.models import (
    ApprovalDecision,
    CanonicalEvent,
    IamIngressRequest,
    RawIngressEnvelope,
    SecurityEvent,
    SignalWorkflowCommand,
    StartWorkflowCommand,
    build_provider_event,
    iam_request_to_canonical,
    to_approval_decision,
    to_canonical_event,
    to_security_event,
    to_workflow_command,
)
from shared.models.common import LifecycleAction
from shared.models.provider_events import DefenderWebhook, TeamsApprovalCallback


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


@pytest.fixture()
def defender_envelope() -> RawIngressEnvelope:
    return RawIngressEnvelope(
        request_id="req-001",
        tenant_id="tenant-demo-001",
        provider="defender",
        route="/api/v1/ingress/defender",
        method="POST",
        headers={"content-type": "application/json"},
        received_at=datetime.now(timezone.utc),
        raw_body={
            "alert_id": "ALT-100",
            "severity": "high",
            "title": "Suspicious login",
            "description": "Multiple failed logins",
            "user_email": "alice@secamo.be",
            "source_ip": "10.0.0.1",
        },
    )


@pytest.fixture()
def teams_envelope() -> RawIngressEnvelope:
    return RawIngressEnvelope(
        request_id="req-002",
        tenant_id="tenant-demo-001",
        provider="teams",
        route="/api/v1/ingress/teams",
        method="POST",
        headers={"content-type": "application/json"},
        received_at=datetime.now(timezone.utc),
        raw_body={
            "workflow_id": "wf-impossible-travel-001",
            "approved": True,
            "reviewer": "analyst@secamo.be",
            "action": "dismiss",
            "comments": "False positive",
        },
    )


class TestDefenderPipeline:
    def test_full_pipeline_to_security_event(self, defender_envelope):
        event = build_provider_event(defender_envelope)
        assert isinstance(event, DefenderWebhook)

        canonical = to_canonical_event(event, defender_envelope)
        assert isinstance(canonical, CanonicalEvent)
        assert canonical.event_type == "defender.alert"

        se = to_security_event(canonical)
        assert isinstance(se, SecurityEvent)
        assert se.tenant_id == "tenant-demo-001"
        assert se.alert is not None
        assert se.alert.alert_id == "ALT-100"
        assert se.user is not None
        assert se.user.user_principal_name == "alice@secamo.be"
        assert se.network is not None
        assert se.network.source_ip == "10.0.0.1"

        cmd = to_workflow_command(canonical)
        assert isinstance(cmd, StartWorkflowCommand)
        assert cmd.workflow_name == "DefenderAlertEnrichmentWorkflow"
        assert isinstance(cmd.workflow_input, SecurityEvent)


class TestTeamsPipeline:
    def test_full_pipeline_signal_unchanged(self, teams_envelope):
        event = build_provider_event(teams_envelope)
        assert isinstance(event, TeamsApprovalCallback)

        canonical = to_canonical_event(event, teams_envelope)
        cmd = to_workflow_command(canonical)

        assert isinstance(cmd, SignalWorkflowCommand)
        assert cmd.workflow_id == "wf-impossible-travel-001"
        assert cmd.signal_name == "approve"

    def test_canonical_to_approval_decision(self, teams_envelope):
        event = build_provider_event(teams_envelope)
        canonical = to_canonical_event(event, teams_envelope)
        decision = to_approval_decision(canonical)

        assert isinstance(decision, ApprovalDecision)
        assert decision.approved is True
        assert decision.action == "dismiss"


class TestIamPipeline:
    def test_full_pipeline_to_security_event(self, cli_payload):
        iam_req = IamIngressRequest.model_validate(cli_payload)
        canonical = iam_request_to_canonical(
            iam_req, tenant_id="tenant-demo-001", request_id="req-iam-001"
        )

        se = to_security_event(canonical)
        assert se.event_type == "iam.onboarding"
        assert se.user is not None
        assert se.user.action == LifecycleAction.CREATE
        assert se.user.user_data is not None
        assert se.user.user_data["email"] == "john.doe@secamo.be"

        cmd = to_workflow_command(canonical)
        assert isinstance(cmd, StartWorkflowCommand)
        assert cmd.workflow_name == "IamOnboardingWorkflow"
        assert isinstance(cmd.workflow_input, SecurityEvent)


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

    def test_raw_ingress_envelope_ignores_unknown(self):
        data = {
            "request_id": "r1",
            "tenant_id": "t1",
            "provider": "test",
            "route": "/test",
            "method": "POST",
            "headers": {},
            "received_at": datetime.now(timezone.utc).isoformat(),
            "raw_body": None,
            "futuristic_field": "v2",
        }
        env = RawIngressEnvelope.model_validate(data)
        assert env.request_id == "r1"
        assert not hasattr(env, "futuristic_field")
