"""
Test suite for the shared.models Pydantic v2 refactor.

Covers:
  1. Dict → LifecycleRequest with action coercion + nested UserData
  2. Defender pipeline:  RawIngressEnvelope → DefenderWebhook → CanonicalEvent → StartWorkflowCommand
  3. Teams pipeline:    RawIngressEnvelope → TeamsApprovalCallback → CanonicalEvent → SignalWorkflowCommand
  4. IAM pipeline:      IamIngressRequest → CanonicalEvent → LifecycleRequest → StartWorkflowCommand
  5. Backwards compat:  CLI payload shape → valid LifecycleRequest, model_dump(mode="json")
  6. Extra fields:      Unknown provider fields don't crash
  7. IAM handler:       Uses ingress_sdk abstractions
"""

from datetime import datetime, timezone

import pytest

from shared.models import (
    # common
    LifecycleAction,
    # domain
    AlertData,
    ApprovalDecision,
    DefenderAlertRequest,
    LifecycleRequest,
    UserData,
    # ingress
    IamIngressRequest,
    RawIngressEnvelope,
    # provider events
    DefenderWebhook,
    TeamsApprovalCallback,
    # canonical
    CanonicalEvent,
    # commands
    SignalWorkflowCommand,
    StartWorkflowCommand,
    # mappers
    build_provider_event,
    iam_request_to_canonical,
    to_approval_decision,
    to_canonical_event,
    to_defender_alert_request,
    to_lifecycle_request,
    to_workflow_command,
)


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture()
def cli_payload() -> dict:
    """The known-good CLI payload that must always work."""
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


# ── Test 1: Dict validates to LifecycleRequest ───────────────

class TestLifecycleRequestFromDict:
    def test_dict_with_string_action(self, cli_payload):
        req = LifecycleRequest(tenant_id="t1", **cli_payload)
        assert req.action == LifecycleAction.CREATE
        assert isinstance(req.user_data, UserData)
        assert req.user_data.email == "john.doe@secamo.be"
        assert req.requester == "admin@secamo.be"
        assert req.ticket_id == "TKT-TEST-001"

    def test_model_validate_from_dict(self, cli_payload):
        full = {"tenant_id": "t1", **cli_payload}
        req = LifecycleRequest.model_validate(full)
        assert req.action == LifecycleAction.CREATE
        assert req.user_data.department == "Engineering"

    def test_list_action_coercion(self, cli_payload):
        """Legacy edge-case: action passed as list of chars."""
        cli_payload["action"] = ["c", "r", "e", "a", "t", "e"]
        req = LifecycleRequest(tenant_id="t1", **cli_payload)
        assert req.action == LifecycleAction.CREATE


# ── Test 2: Defender pipeline ─────────────────────────────────

class TestDefenderPipeline:
    def test_full_pipeline(self, defender_envelope):
        # Envelope → ProviderEvent
        event = build_provider_event(defender_envelope)
        assert isinstance(event, DefenderWebhook)
        assert event.alert_id == "ALT-100"
        assert event.severity == "high"

        # ProviderEvent → CanonicalEvent
        canonical = to_canonical_event(event, defender_envelope)
        assert isinstance(canonical, CanonicalEvent)
        assert canonical.event_type == "defender.alert"
        assert canonical.tenant_id == "tenant-demo-001"
        assert canonical.payload["alert_id"] == "ALT-100"

        # CanonicalEvent → StartWorkflowCommand
        cmd = to_workflow_command(canonical)
        assert isinstance(cmd, StartWorkflowCommand)
        assert cmd.command_type == "start_workflow"
        assert cmd.workflow_name == "DefenderAlertEnrichmentWorkflow"
        assert cmd.task_queue == "soc-defender"

    def test_canonical_to_defender_alert_request(self, defender_envelope):
        event = build_provider_event(defender_envelope)
        canonical = to_canonical_event(event, defender_envelope)
        dar = to_defender_alert_request(canonical)
        assert isinstance(dar, DefenderAlertRequest)
        assert isinstance(dar.alert, AlertData)
        assert dar.alert.alert_id == "ALT-100"


# ── Test 3: Teams pipeline ────────────────────────────────────

class TestTeamsPipeline:
    def test_full_pipeline(self, teams_envelope):
        # Envelope → ProviderEvent
        event = build_provider_event(teams_envelope)
        assert isinstance(event, TeamsApprovalCallback)
        assert event.approved is True
        assert event.reviewer == "analyst@secamo.be"

        # ProviderEvent → CanonicalEvent
        canonical = to_canonical_event(event, teams_envelope)
        assert canonical.event_type == "teams.approval_callback"

        # CanonicalEvent → SignalWorkflowCommand
        cmd = to_workflow_command(canonical)
        assert isinstance(cmd, SignalWorkflowCommand)
        assert cmd.command_type == "signal_workflow"
        assert cmd.workflow_id == "wf-impossible-travel-001"
        assert cmd.signal_name == "approve"

    def test_canonical_to_approval_decision(self, teams_envelope):
        event = build_provider_event(teams_envelope)
        canonical = to_canonical_event(event, teams_envelope)
        decision = to_approval_decision(canonical)
        assert isinstance(decision, ApprovalDecision)
        assert decision.approved is True
        assert decision.action == "dismiss"


# ── Test 4: IAM pipeline ─────────────────────────────────────

class TestIamPipeline:
    def test_full_pipeline(self, cli_payload):
        # Body → IamIngressRequest
        iam_req = IamIngressRequest.model_validate(cli_payload)
        assert iam_req.action == "create"
        assert iam_req.user_data["email"] == "john.doe@secamo.be"

        # IamIngressRequest → CanonicalEvent
        canonical = iam_request_to_canonical(
            iam_req, tenant_id="tenant-demo-001", request_id="req-iam-001",
        )
        assert canonical.event_type == "iam.onboarding"
        assert canonical.tenant_id == "tenant-demo-001"

        # CanonicalEvent → LifecycleRequest
        lifecycle = to_lifecycle_request(canonical)
        assert isinstance(lifecycle, LifecycleRequest)
        assert lifecycle.action == LifecycleAction.CREATE
        assert lifecycle.user_data.email == "john.doe@secamo.be"
        assert lifecycle.ticket_id == "TKT-TEST-001"

        # CanonicalEvent → StartWorkflowCommand
        cmd = to_workflow_command(canonical)
        assert isinstance(cmd, StartWorkflowCommand)
        assert cmd.workflow_name == "IamOnboardingWorkflow"
        assert cmd.task_queue == "iam-graph"


# ── Test 5: Backwards compatibility ──────────────────────────

class TestBackwardsCompat:
    def test_cli_payload_shape(self, cli_payload):
        """LifecycleRequest from the exact CLI payload used in production."""
        req = LifecycleRequest(tenant_id="tenant-demo-001", **cli_payload)
        assert req.action == LifecycleAction.CREATE
        assert req.user_data.email == "john.doe@secamo.be"
        assert req.user_data.department == "Engineering"
        assert req.user_data.role == "Developer"
        assert req.requester == "admin@secamo.be"
        assert req.ticket_id == "TKT-TEST-001"

    def test_model_dump_json_mode(self, cli_payload):
        """model_dump(mode='json') produces JSON-safe output matching old shape."""
        req = LifecycleRequest(tenant_id="tenant-demo-001", **cli_payload)
        dumped = req.model_dump(mode="json")

        # action should be the string value, not an Enum
        assert dumped["action"] == "create"
        assert isinstance(dumped["action"], str)

        # user_data should be a plain dict
        assert isinstance(dumped["user_data"], dict)
        assert dumped["user_data"]["email"] == "john.doe@secamo.be"

        # All expected keys present
        assert set(dumped.keys()) == {"tenant_id", "action", "user_data", "requester", "ticket_id"}

    def test_default_ticket_id(self):
        """ticket_id defaults to empty string when omitted."""
        req = LifecycleRequest(
            tenant_id="t1",
            action="create",
            user_data={
                "email": "a@b.com",
                "first_name": "A",
                "last_name": "B",
                "department": "X",
                "role": "Y",
            },
            requester="admin",
        )
        assert req.ticket_id == ""


# ── Test 6: Extra fields ignored ──────────────────────────────

class TestExtraFieldsIgnored:
    def test_defender_webhook_ignores_unknown_fields(self):
        data = {
            "provider": "defender",
            "event_name": "defender.webhook",
            "alert_id": "ALT-1",
            "severity": "low",
            "title": "Test",
            "raw_payload": {},
            "unknown_field_1": "should be ignored",
            "another_unknown": 42,
        }
        webhook = DefenderWebhook.model_validate(data)
        assert webhook.alert_id == "ALT-1"
        assert not hasattr(webhook, "unknown_field_1")

    def test_teams_callback_ignores_unknown_fields(self):
        data = {
            "provider": "teams",
            "event_name": "teams.callback",
            "workflow_id": "wf-001",
            "approved": False,
            "reviewer": "user@test.com",
            "action": "isolate",
            "raw_payload": {},
            "extra_field": "ignored",
        }
        callback = TeamsApprovalCallback.model_validate(data)
        assert callback.workflow_id == "wf-001"
        assert not hasattr(callback, "extra_field")

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


# ── Test 7: IAM handler uses ingress_sdk abstractions ─────────

class TestIamHandlerIntegration:
    """Verify the handler module follows ingress_sdk conventions."""

    def test_handler_imports_from_ingress_sdk(self):
        """The handler must import temporal, response, async_handler, IngressEvent
        from ingress_sdk — not build its own Temporal client."""
        import importlib
        import inspect

        # We can't actually import handler.py without the Lambda Layer on sys.path,
        # so we read the source and inspect it textually.
        handler_path = (
            r"c:\Users\ghost\Documents\repos\secamo-poc\secamo-poc"
            r"\terraform\modules\ingress\src\ingress\handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            source = f.read()

        # Must use ingress_sdk abstractions
        assert "from ingress_sdk import temporal, response" in source
        assert "from ingress_sdk.dispatch import async_handler" in source
        assert "from ingress_sdk.event import IngressEvent" in source

        # Must NOT create its own Temporal client
        assert "Client.connect" not in source
        assert "temporalio.client" not in source

    def test_handler_registers_iam_route(self):
        handler_path = (
            r"c:\Users\ghost\Documents\repos\secamo-poc\secamo-poc"
            r"\terraform\modules\ingress\src\ingress\handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            source = f.read()

        assert '"/api/v1/ingress/iam"' in source
        assert "handle_iam" in source

    def test_handler_validates_with_pydantic(self):
        handler_path = (
            r"c:\Users\ghost\Documents\repos\secamo-poc\secamo-poc"
            r"\terraform\modules\ingress\src\ingress\handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            source = f.read()

        assert "IamIngressRequest.model_validate" in source
        assert 'model_dump(mode="json")' in source

    def test_handler_uses_response_accepted(self):
        handler_path = (
            r"c:\Users\ghost\Documents\repos\secamo-poc\secamo-poc"
            r"\terraform\modules\ingress\src\ingress\handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            source = f.read()

        assert "response.accepted(" in source
        assert "temporal.start_workflow(" in source
