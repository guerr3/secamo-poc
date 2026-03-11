"""
Proxy Lambda — Front Door Ingress (Temporal Client)

Routes:
  POST /api/v1/ingress/defender → Start DefenderAlertEnrichmentWorkflow
  POST /api/v1/ingress/teams   → Signal active workflow (approve)
  POST /api/v1/ingress/iam     → Start IamOnboardingWorkflow

All infrastructure (Temporal client, event parsing, response formatting,
async dispatch) is provided by the ingress_sdk Lambda Layer.
"""

from ingress_sdk import temporal, response
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

from shared.models import IamIngressRequest, LifecycleRequest, LifecycleAction, UserData
from ingress.mappers import normalize_event_body


PROVIDER_EVENT_ROUTING = {
    ("microsoft_defender", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_defender", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("crowdstrike", "detection_summary"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("crowdstrike", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("sentinelone", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("jira", "jira:issue_created"): ("IamOnboardingWorkflow", "iam-graph"),
    ("jira", "jira:issue_updated"): ("IamOnboardingWorkflow", "iam-graph"),
}


# ── Route: /api/v1/ingress/defender ──────────────────────────

async def handle_defender(event: IngressEvent) -> dict:
    """Start a DefenderAlertEnrichmentWorkflow on the soc-defender queue."""
    normalized = normalize_event_body(
        provider="microsoft_defender",
        event_type="alert",
        tenant_id=event.tenant_id,
        raw_body=event.body,
    )

    result = await temporal.start_workflow(
        workflow="DefenderAlertEnrichmentWorkflow",
        input=normalized,
        tenant_id=event.tenant_id,
        task_queue="soc-defender",
    )
    return response.accepted(result)


# ── Route: /api/v1/ingress/teams ─────────────────────────────

async def handle_teams(event: IngressEvent) -> dict:
    """Send an 'approve' signal to an active workflow."""
    workflow_id = event.body.get("workflow_id")
    if not workflow_id:
        return response.error(400, "workflow_id is required in the request body")

    result = await temporal.signal_workflow(
        workflow_id=workflow_id,
        signal="approve",
        payload={
            "approved": event.body.get("approved", True),
            "reviewer": event.body.get("reviewer", "teams-user"),
            "action": event.body.get("action", "dismiss"),
            "comments": event.body.get("comments", ""),
        },
    )
    return response.ok(result)


# ── Route: /api/v1/ingress/iam ───────────────────────────────

async def handle_iam(event: IngressEvent) -> dict:
    """Validate an IAM request and start an IamOnboardingWorkflow."""

    # 1. Validate request body with Pydantic ingress model
    try:
        iam_request = IamIngressRequest.model_validate(event.body)
    except Exception as exc:
        return response.error(400, f"Invalid IAM request body: {exc}")

    normalized = normalize_event_body(
        provider="microsoft_graph",
        event_type="iam_request",
        tenant_id=event.tenant_id,
        raw_body=iam_request.model_dump(mode="json"),
    )

    # 2. Build domain LifecycleRequest (tenant_id from authorizer, rest from body)
    try:
        lifecycle = LifecycleRequest(
            tenant_id=event.tenant_id,
            action=LifecycleAction(normalized["action"]),
            user_data=UserData.model_validate(normalized["user_data"]),
            requester=normalized["requester"],
            ticket_id=normalized.get("ticket_id", ""),
            source_provider=normalized.get("source_provider", "microsoft_graph"),
        )
    except Exception as exc:
        return response.error(400, f"Invalid lifecycle payload: {exc}")

    # 3. Start workflow via ingress_sdk (model_dump(mode="json") for JSON-safe serialization)
    result = await temporal.start_workflow(
        workflow="IamOnboardingWorkflow",
        input=lifecycle.model_dump(mode="json"),
        tenant_id=event.tenant_id,
        task_queue="iam-graph",
    )
    return response.accepted(result)


async def handle_generic_event(event: IngressEvent) -> dict:
    """Generic provider-event ingress route for workflow starts."""
    provider = str(event.body.get("provider", "")).strip().lower()
    if not provider:
        return response.error(400, "provider is required in request body")

    event_type = str(event.body.get("event_type", "alert")).strip().lower() or "alert"
    routing = PROVIDER_EVENT_ROUTING.get((provider, event_type))
    if routing is None:
        return response.error(
            400,
            f"No workflow mapping found for provider='{provider}' event_type='{event_type}'",
        )

    workflow_name, task_queue = routing
    normalized = normalize_event_body(
        provider=provider,
        event_type=event_type,
        tenant_id=event.tenant_id,
        raw_body=event.body,
    )

    result = await temporal.start_workflow(
        workflow=workflow_name,
        input=normalized,
        tenant_id=event.tenant_id,
        task_queue=task_queue,
    )
    return response.accepted(result)


# ── Lambda Entrypoint ────────────────────────────────────────

handler = async_handler({
    "/api/v1/ingress/defender": handle_defender,
    "/api/v1/ingress/teams": handle_teams,
    "/api/v1/ingress/iam": handle_iam,
    "/api/v1/ingress/event": handle_generic_event,
})
