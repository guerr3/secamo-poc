"""
Proxy Lambda — Front Door Ingress (Temporal Client)

Routes:
  POST /api/v1/ingress/defender → Start DefenderAlertEnrichmentWorkflow
  POST /api/v1/ingress/teams   → Signal active workflow (approve)
  POST /api/v1/ingress/iam     → Start IamOnboardingWorkflow

All infrastructure (Temporal client, event parsing, response formatting,
async dispatch) is provided by the ingress_sdk Lambda Layer.
"""

from pydantic import ValidationError
from ingress_sdk import temporal, response
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

from shared.models import IamIngressRequest, LifecycleRequest, LifecycleAction, UserData


# ── Route: /api/v1/ingress/defender ──────────────────────────

async def handle_defender(event: IngressEvent) -> dict:
    """Start a DefenderAlertEnrichmentWorkflow on the soc-defender queue."""
    result = await temporal.start_workflow(
        workflow="DefenderAlertEnrichmentWorkflow",
        input={
            "tenant_id": event.tenant_id,
            "alert": event.body.get("alert", {}),
            "requester": event.body.get("requester", "ingress-api"),
        },
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

    # 2. Build domain LifecycleRequest (tenant_id from authorizer, rest from body)
    try:
        lifecycle = LifecycleRequest(
            tenant_id=event.tenant_id,
            action=LifecycleAction(iam_request.action),
            user_data=UserData.model_validate(iam_request.user_data),
            requester=iam_request.requester,
            ticket_id=iam_request.ticket_id or "",
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


# ── Lambda Entrypoint ────────────────────────────────────────

handler = async_handler({
    "/api/v1/ingress/defender": handle_defender,
    "/api/v1/ingress/teams": handle_teams,
    "/api/v1/ingress/iam": handle_iam,
})
