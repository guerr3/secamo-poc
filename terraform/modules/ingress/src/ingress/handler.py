"""
Proxy Lambda — Front Door Ingress (Temporal Client)

Routes:
  POST /api/v1/ingress/defender → Start DefenderAlertEnrichmentWorkflow
  POST /api/v1/ingress/teams   → Signal active workflow (approve)
  POST /api/v1/ingress/iam     → Start IamOnboardingWorkflow
    GET  /api/v1/hitl/respond    → Consume signed email approval token
    POST /api/v1/hitl/jira       → Consume Jira webhook approval callback

All infrastructure (Temporal client, event parsing, response formatting,
async dispatch) is provided by the ingress_sdk Lambda Layer.
"""

import hashlib
import hmac
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError

from ingress_sdk import temporal, response
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

from shared.models import IamIngressRequest
from mappers import normalize_event_body


_dynamo = boto3.client("dynamodb", region_name="eu-west-1")
_ssm = boto3.client("ssm", region_name="eu-west-1")
logger = logging.getLogger("ingress.hitl")


def _html_response(status_code: int, body: str) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": body,
    }


def _find_header(headers: dict, key: str) -> str:
    wanted = key.lower()
    for header_name, value in (headers or {}).items():
        if str(header_name).lower() == wanted:
            return str(value)
    return ""


def _extract_comment_text(comment_block: dict) -> str:
    comments = ((comment_block or {}).get("comments") or [])
    if not comments:
        return ""

    body = (comments[0] or {}).get("body")
    if isinstance(body, str):
        return body.strip()

    if isinstance(body, dict):
        content = body.get("content") or []
        text_parts: list[str] = []
        for node in content:
            for item in (node.get("content") or []):
                text = item.get("text")
                if text:
                    text_parts.append(str(text))
        return " ".join(text_parts).strip()

    return ""


def _parse_action_from_text(raw_text: str) -> str:
    value = (raw_text or "").strip().lower().replace(" ", "_")
    allowed = {"dismiss", "isolate", "disable_user"}
    if value in allowed:
        return value
    for candidate in allowed:
        if candidate in value:
            return candidate
    return "dismiss"


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


# ── Route: /api/v1/hitl/respond ─────────────────────────────

async def handle_hitl_respond(event: IngressEvent) -> dict:
    token = (event.query_params or {}).get("token")
    action = (event.query_params or {}).get("action")
    if not token or not action:
        return _html_response(
            400,
            "<html><body><h3>Invalid request</h3><p>Missing token or action.</p></body></html>",
        )

    table_name = os.environ.get("HITL_TOKEN_TABLE", "").strip()
    if not table_name:
        return _html_response(
            500,
            "<html><body><h3>Configuration error</h3><p>HITL token table is not configured.</p></body></html>",
        )

    now_epoch = int(time.time())
    token_preview = f"{str(token)[:8]}..."
    logger.info("HiTL respond received token=%s action=%s", token_preview, action)

    try:
        update_result = _dynamo.update_item(
            TableName=table_name,
            Key={"token": {"S": str(token)}},
            UpdateExpression="SET used = :used",
            ConditionExpression="attribute_exists(#token) AND used = :unused AND expires_at > :now_epoch",
            ExpressionAttributeNames={"#token": "token"},
            ExpressionAttributeValues={
                ":used": {"BOOL": True},
                ":unused": {"BOOL": False},
                ":now_epoch": {"N": str(now_epoch)},
            },
            ReturnValues="ALL_OLD",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            logger.warning("HiTL respond rejected token=%s reason=expired_or_used", token_preview)
            return _html_response(
                410,
                "<html><body><h3>Link expired</h3><p>This link has expired or already been used.</p></body></html>",
            )
        logger.exception("HiTL respond failed token=%s", token_preview)
        return _html_response(
            500,
            "<html><body><h3>Internal error</h3><p>Unable to process approval link.</p></body></html>",
        )

    attrs = update_result.get("Attributes", {})
    allowed_actions = set((attrs.get("allowed_actions") or {}).get("SS", []))
    if str(action) not in allowed_actions:
        logger.warning("HiTL respond forbidden token=%s action=%s", token_preview, action)
        return _html_response(
            403,
            "<html><body><h3>Forbidden</h3><p>Action is not allowed for this approval request.</p></body></html>",
        )

    workflow_id = (attrs.get("workflow_id") or {}).get("S", "")
    reviewer_email = (attrs.get("reviewer_email") or {}).get("S", "unknown")
    if not workflow_id:
        return _html_response(
            500,
            "<html><body><h3>Internal error</h3><p>Workflow mapping missing for token.</p></body></html>",
        )

    payload = {
        "approved": str(action) != "dismiss",
        "reviewer": f"email:{reviewer_email}",
        "action": str(action),
        "comments": "Approved via signed email link",
    }

    await temporal.signal_workflow(
        workflow_id=workflow_id,
        signal="approve",
        payload=payload,
    )
    logger.info("HiTL respond signaled workflow_id=%s token=%s", workflow_id, token_preview)

    return _html_response(
        200,
        "<html><body><h3>Decision recorded</h3><p>Decision recorded. Close this tab.</p></body></html>",
    )


# ── Route: /api/v1/hitl/jira ───────────────────────────────

async def handle_hitl_jira(event: IngressEvent) -> dict:
    body = event.body or {}
    tenant_id = body.get("tenant_id") or "test-tenant"

    signature = _find_header(event.headers, "x-hub-signature-256")
    if not signature:
        return response.error(401, "Missing x-hub-signature-256")

    secret_path = f"/secamo/tenants/{tenant_id}/hitl/jira_webhook_secret"
    try:
        secret_resp = _ssm.get_parameter(Name=secret_path, WithDecryption=True)
        shared_secret = secret_resp.get("Parameter", {}).get("Value", "")
    except ClientError:
        return response.error(401, "Invalid webhook signature")

    expected = "sha256=" + hmac.new(
        shared_secret.encode("utf-8"),
        (event.raw_body or "").encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        return response.error(401, "Invalid webhook signature")

    issue = body.get("issue") or {}
    fields = issue.get("fields") or {}
    issue_key = issue.get("key") or ""
    status_name = ((fields.get("status") or {}).get("name") or "").strip()
    labels = fields.get("labels") or []

    workflow_id = ""
    for label in labels:
        if str(label).startswith("secamo-wf:"):
            workflow_id = str(label).split(":", 1)[1]
            break

    if not workflow_id:
        return response.ok({"skipped": "no secamo-wf label"})

    approved = status_name.lower() in {"approved", "resolved"}
    first_comment_text = _extract_comment_text(body.get("comment") or {})
    action = _parse_action_from_text(first_comment_text)

    payload = {
        "approved": approved,
        "reviewer": f"jira:{issue_key or 'unknown'}",
        "action": action,
        "comments": first_comment_text or "Approved via Jira webhook",
    }

    await temporal.signal_workflow(
        workflow_id=workflow_id,
        signal="approve",
        payload=payload,
    )
    return response.ok({"signaled": workflow_id})


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

    # 2. Start workflow via ingress_sdk with universal SecurityEvent payload shape.
    result = await temporal.start_workflow(
        workflow="IamOnboardingWorkflow",
        input=normalized,
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
    "/api/v1/hitl/respond": handle_hitl_respond,
    "/api/v1/hitl/jira": handle_hitl_jira,
})
