"""Default code-defined workflow route mappings.

Responsibility: construct route registry entries used by ingress fan-out dispatch.
This module must not include payload normalization logic or SDK dispatch implementations.
"""

from __future__ import annotations

from shared.routing.contracts import WorkflowRoute
from shared.routing.registry import RouteRegistry


def build_default_route_registry() -> RouteRegistry:
    """Build default in-memory route registry for currently supported providers/events."""

    registry = RouteRegistry()

    registry.register(
        "microsoft_defender",
        "alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "microsoft_defender",
        "impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "crowdstrike",
        "detection_summary",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "crowdstrike",
        "impossible_travel",
        (WorkflowRoute(workflow_name="ImpossibleTravelWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "sentinelone",
        "alert",
        (WorkflowRoute(workflow_name="DefenderAlertEnrichmentWorkflow", task_queue="soc-defender"),),
    )
    registry.register(
        "jira",
        "jira:issue_created",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue="iam-graph"),),
    )
    registry.register(
        "jira",
        "jira:issue_updated",
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
        "iam_request",
        (WorkflowRoute(workflow_name="IamOnboardingWorkflow", task_queue="iam-graph"),),
    )

    return registry
