"""Default code-defined workflow route mappings.

Responsibility: construct route registry entries used by ingress fan-out dispatch.
This module must not include payload normalization logic or SDK dispatch implementations.
"""

from __future__ import annotations

from typing import Any

from shared.config import QUEUE_IAM, QUEUE_SOC
from shared.models.canonical import Envelope
from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry


def _is_critical_defender_alert(envelope: Envelope) -> bool:
    """Route high-severity defender findings through explicit rule precedence."""

    if envelope.payload.event_type != "defender.alert":
        return False
    return envelope.payload.severity_id >= 60


def build_default_route_registry() -> RouteRegistry:
    """Build default in-memory route registry for currently supported providers/events."""

    registry = RouteRegistry()

    # Explicit rules are evaluated before event-type fallback routes.
    registry.register_rule(
        name="critical-defender-alert",
        predicate=_is_critical_defender_alert,
        routes=(WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )

    registry.register(
        "microsoft_defender",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "microsoft_defender",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "microsoft_defender",
        "alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "microsoft_defender",
        "impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "crowdstrike",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "crowdstrike",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "crowdstrike",
        "detection_summary",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "crowdstrike",
        "impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "sentinelone",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "sentinelone",
        "alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "jira",
        "iam.onboarding",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_IAM),),
    )
    registry.register(
        "jira",
        "jira:issue_created",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_IAM),),
    )
    registry.register(
        "jira",
        "jira:issue_updated",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_IAM),),
    )
    registry.register(
        "microsoft_graph",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "microsoft_graph",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "microsoft_graph",
        "iam.onboarding",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_IAM),),
    )
    registry.register(
        "microsoft_graph",
        "iam_request",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue=QUEUE_IAM),),
    )
    registry.register(
        "defender",
        "alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )
    registry.register(
        "defender",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue=QUEUE_SOC),),
    )

    registry.register_polling_resource("microsoft_defender", "defender_alerts", "alert")
    registry.register_polling_resource("microsoft_defender", "entra_signin_logs", "impossible_travel")

    registry.register_webhook_resource("microsoft_graph", "security/alerts", "defender.alert")
    registry.register_webhook_resource("microsoft_graph", "security/alerts_v2", "defender.alert")
    registry.register_webhook_resource("microsoft_graph", "auditlogs/signins", "defender.impossible_travel")
    registry.register_webhook_resource("microsoft_graph", "identityprotection/riskyusers", "defender.impossible_travel")

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
