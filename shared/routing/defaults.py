"""Default code-defined workflow route mappings.

Responsibility: construct route registry entries used by ingress fan-out dispatch.
This module must not include payload normalization logic or SDK dispatch implementations.
"""

from __future__ import annotations

from typing import Any

from shared.config import QUEUE_EDR, QUEUE_USER_LIFECYCLE
from shared.models.canonical import Envelope
from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry


def _is_critical_defender_alert(envelope: Envelope) -> bool:
    """Route high-severity defender findings through explicit rule precedence."""

    if envelope.payload.event_type != "defender.alert":
        return False
    return envelope.payload.severity_id >= 60


def _is_signin_log_signal(envelope: Envelope) -> bool:
    payload = envelope.payload
    return (
        getattr(payload, "event_type", None) == "defender.security_signal"
        and getattr(payload, "provider_event_type", None) == "signin_log"
    )


def _is_risky_user_signal(envelope: Envelope) -> bool:
    payload = envelope.payload
    return (
        getattr(payload, "event_type", None) == "defender.security_signal"
        and getattr(payload, "provider_event_type", None) == "risky_user"
    )


def _is_noncompliant_device_signal(envelope: Envelope) -> bool:
    payload = envelope.payload
    return (
        getattr(payload, "event_type", None) == "defender.security_signal"
        and getattr(payload, "provider_event_type", None) == "noncompliant_device"
    )


def _is_audit_log_signal(envelope: Envelope) -> bool:
    payload = envelope.payload
    return (
        getattr(payload, "event_type", None) == "defender.security_signal"
        and getattr(payload, "provider_event_type", None) == "audit_log"
    )


def build_default_route_registry() -> RouteRegistry:
    """Build default in-memory route registry for currently supported providers/events."""

    registry = RouteRegistry()

    # Explicit rules are evaluated before event-type fallback routes.
    registry.register_rule(
        name="critical-defender-alert",
        predicate=_is_critical_defender_alert,
        routes=(WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register_rule(
        name="signin-log-signal",
        predicate=_is_signin_log_signal,
        routes=(WorkflowRoute(workflow_name="SigninAnomalyDetectionWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register_rule(
        name="risky-user-signal",
        predicate=_is_risky_user_signal,
        routes=(WorkflowRoute(workflow_name="RiskyUserTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register_rule(
        name="noncompliant-device-signal",
        predicate=_is_noncompliant_device_signal,
        routes=(WorkflowRoute(workflow_name="DeviceComplianceRemediationWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register_rule(
        name="audit-log-signal",
        predicate=_is_audit_log_signal,
        routes=(WorkflowRoute(workflow_name="AuditLogAnomalyWorkflow", task_queue=QUEUE_EDR),),
    )

    registry.register(
        "microsoft_defender",
        "defender.alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "microsoft_defender",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "microsoft_defender",
        "alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "microsoft_defender",
        "defender.security_signal",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "crowdstrike",
        "defender.alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "crowdstrike",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "crowdstrike",
        "detection_summary",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "crowdstrike",
        "impossible_travel",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "sentinelone",
        "defender.alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "sentinelone",
        "alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "jira",
        "iam.onboarding",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_USER_LIFECYCLE),),
    )
    registry.register(
        "jira",
        "jira:issue_created",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_USER_LIFECYCLE),),
    )
    registry.register(
        "jira",
        "jira:issue_updated",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_USER_LIFECYCLE),),
    )
    registry.register(
        "microsoft_graph",
        "defender.alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "microsoft_graph",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "microsoft_graph",
        "defender.security_signal",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "microsoft_graph",
        "security_signal",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "microsoft_graph",
        "iam.onboarding",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_USER_LIFECYCLE),),
    )
    registry.register(
        "microsoft_graph",
        "iam_request",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_USER_LIFECYCLE),),
    )
    registry.register(
        "defender",
        "alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )
    registry.register(
        "defender",
        "defender.alert",
        (WorkflowRoute(workflow_name="SocAlertTriageWorkflow", task_queue=QUEUE_EDR),),
    )

    registry.register_polling_resource("microsoft_defender", "defender_alerts", "alert")
    registry.register_polling_resource("microsoft_defender", "entra_signin_logs", "signin_log")
    registry.register_polling_resource("microsoft_defender", "entra_risky_users", "risky_user")
    registry.register_polling_resource("microsoft_defender", "intune_noncompliant_devices", "noncompliant_device")
    registry.register_polling_resource("microsoft_defender", "entra_audit_logs", "audit_log")

    registry.register_webhook_resource("microsoft_graph", "security/alerts", "defender.alert")
    registry.register_webhook_resource("microsoft_graph", "security/alerts_v2", "defender.alert")
    registry.register_webhook_resource("microsoft_graph", "auditlogs/signins", "defender.impossible_travel")
    registry.register_webhook_resource("microsoft_graph", "identityprotection/riskyusers", "defender.security_signal")

    return registry


def _first_route(routes: tuple[WorkflowRoute, ...]) -> tuple[str, str] | None:
    if not routes:
        return None
    route = routes[0]
    return route.workflow_name, route.task_queue


def resolve_provider_event_route(
    provider: str,
    event_type: str,
    *,
    route_registry: RouteRegistry | None = None,
) -> tuple[str, str] | None:
    """Resolve one workflow route for provider event tuples using routing defaults."""

    registry = route_registry or build_default_route_registry()
    return _first_route(registry.resolve_provider_event(provider, event_type))


def resolve_polling_route(
    provider: str,
    resource_type: str,
    payload: Any | None = None,
    *,
    route_registry: RouteRegistry | None = None,
) -> tuple[str, str] | None:
    """Resolve polling routes from routing defaults."""

    registry = route_registry or build_default_route_registry()
    return _first_route(registry.resolve_polling(provider, resource_type, payload))


def resolve_webhook_route(
    provider: str,
    resource_type: str,
    payload: dict[str, Any] | None = None,
    *,
    route_registry: RouteRegistry | None = None,
) -> tuple[str, str] | None:
    """Resolve webhook routes from routing defaults."""

    registry = route_registry or build_default_route_registry()
    return _first_route(registry.resolve_webhook(provider, resource_type, payload))
