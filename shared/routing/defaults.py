"""Default code-defined workflow route mappings.

Responsibility: construct route registry entries used by ingress fan-out dispatch.
This module must not include payload normalization logic or SDK dispatch implementations.
"""

from __future__ import annotations

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
        routes=(WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )

    registry.register(
        "microsoft_defender",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "microsoft_defender",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "crowdstrike",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "crowdstrike",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "sentinelone",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "jira",
        "iam.onboarding",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue="iam-graph"),),
    )
    registry.register(
        "microsoft_graph",
        "defender.alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "microsoft_graph",
        "defender.impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "microsoft_graph",
        "iam.onboarding",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue="iam-graph"),),
    )

    return registry
