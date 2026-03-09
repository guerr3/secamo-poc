"""
Proxy Lambda — Front Door Ingress (Temporal Client)

Routes:
  POST /api/v1/ingress/defender → Start DefenderAlertEnrichmentWorkflow
  POST /api/v1/ingress/teams    → Signal active workflow (approve)
  POST /api/v1/ingress/iam      → Start IamOnboardingWorkflow
"""

from pydantic import ValidationError
from ingress_sdk import temporal, response
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

# Import the new Pydantic v2 models
from shared.models import IamIngressRequest, LifecycleRequest


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
    """Validate input via Pydantic and start an IamOnboardingWorkflow."""
    try:
        # 1. Pydantic Type Coercion & Validation at the edge
        ingress_req = IamIngressRequest(**event.body)
        
        # 2. Map to Domain model, inheriting the securely injected tenant_id
        lifecycle_req = LifecycleRequest(
            tenant_id=event.tenant_id,  # Secure context passed down from authorizer
            action=ingress_req.action,
            user_data=ingress_req.user_data,
            requester=ingress_req.requester,
            ticket_id=ingress_req.ticket_id
        )
    except ValidationError as e:
        # Catch strict Pydantic errors and return a clean 400 Bad Request
        return response.error(400, f"Invalid IAM payload: {e.errors()}")

    # 3. Dispatch to Temporal with pure JSON serialization
    result = await temporal.start_workflow(
        workflow="IamOnboardingWorkflow",
        input=lifecycle_req.model_dump(mode="json"),
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