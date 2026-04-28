"""
Proxy Lambda front-door ingress handler.

Routes:
    POST /api/v1/ingress/event/{tenant_id}        -> shared ingress webhook pipeline
    POST /api/v1/graph/notifications/{tenant_id}  -> shared ingress graph pipeline
    POST /api/v1/ingress/internal                  -> shared ingress internal pipeline
    GET  /api/v1/hitl/respond                      -> HiTL callback token flow
    POST /api/v1/hitl/jira/{tenant_id}             -> HiTL Jira callback flow

Responsibility: transport adaptation only for ingress routes. Orchestration lives in shared.ingress.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time

import boto3
import jwt
from botocore.exceptions import ClientError

from ingress_sdk import response, temporal
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

from shared.auth import CachedSecretResolver, build_default_validator_registry
from shared.ingress import GraphNotificationHelper, IngressPipeline
from shared.models import IamIngressRequest
from shared.routing import build_default_route_registry
from shared.temporal.dispatcher import RouteFanoutDispatcher, WorkflowStarter

_dynamo = None
_ssm = None
logger = logging.getLogger("ingress.hitl")

GRAPH_NOTIFICATION_AZP = "0bf30f3b-4a52-48df-9a82-234910c4a086"
GRAPH_COMMON_JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
GRAPH_NOTIFICATION_APP_IDS = {
    value.strip() for value in os.environ.get("GRAPH_NOTIFICATION_APP_IDS", "").split(",") if value.strip()
}
_graph_jwks_client = jwt.PyJWKClient(GRAPH_COMMON_JWKS_URL)
_auth_resolver = None
_auth_registry = None
_ingress_pipeline = None


def _get_dynamo_client():
    """Return a lazily created DynamoDB client to avoid import-time AWS auth resolution."""

    global _dynamo
    if _dynamo is None:
        _dynamo = boto3.client("dynamodb", region_name="eu-west-1")
    return _dynamo


def _get_ssm_client():
    """Return a lazily created SSM client to avoid import-time AWS auth resolution."""

    global _ssm
    if _ssm is None:
        _ssm = boto3.client("ssm", region_name="eu-west-1")
    return _ssm


def _get_auth_registry():
    global _auth_resolver, _auth_registry
    if _auth_registry is None:
        _auth_resolver = CachedSecretResolver()
        _auth_registry = build_default_validator_registry(_auth_resolver)
    return _auth_registry


class _IngressSdkWorkflowStarter(WorkflowStarter):
    """Workflow starter adapter bridging route fan-out to ingress_sdk temporal starts."""

    async def start(
        self,
        *,
        workflow_name: str,
        workflow_input: dict,
        task_queue: str,
        tenant_id: str,
        workflow_id: str,
    ) -> dict:
        return await temporal.start_workflow(
            workflow=workflow_name,
            input=workflow_input,
            tenant_id=tenant_id,
            task_queue=task_queue,
            workflow_id=workflow_id,
        )


_route_fanout_dispatcher = RouteFanoutDispatcher(
    route_registry=build_default_route_registry(),
    workflow_starter=_IngressSdkWorkflowStarter(),
)


def _get_ingress_pipeline() -> IngressPipeline:
    global _ingress_pipeline
    if _ingress_pipeline is None:
        _ingress_pipeline = IngressPipeline(
            auth_registry=_get_auth_registry(),
            route_fanout_dispatcher=_route_fanout_dispatcher,
            graph_helper=GraphNotificationHelper(
                graph_jwks_client=_graph_jwks_client,
                notification_app_ids=GRAPH_NOTIFICATION_APP_IDS,
                notification_azp=GRAPH_NOTIFICATION_AZP,
            ),
        )
    return _ingress_pipeline


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


def _extract_hitl_callback_fields(event: IngressEvent) -> tuple[str, str, str, str, str]:
    """Extract callback token/action/identity fields from GET query or POST body."""

    query = event.query_params or {}
    body = event.body if isinstance(event.body, dict) else {}
    nested = body.get("data") if isinstance(body.get("data"), dict) else {}

    token = str(
        nested.get("token")
        or body.get("token")
        or query.get("token")
        or ""
    ).strip()

    action = str(
        nested.get("action")
        or nested.get("action_taken")
        or nested.get("action_id")
        or body.get("action")
        or body.get("action_taken")
        or body.get("action_id")
        or query.get("action")
        or ""
    ).strip()

    callback_workflow_id = str(
        nested.get("workflow_id")
        or body.get("workflow_id")
        or query.get("workflow_id")
        or ""
    ).strip()

    callback_reviewer = str(
        nested.get("reviewer")
        or nested.get("actor")
        or nested.get("user")
        or body.get("reviewer")
        or body.get("actor")
        or body.get("user")
        or ""
    ).strip()

    callback_comments = str(
        nested.get("comments")
        or body.get("comments")
        or ""
    ).strip()

    return token, action, callback_workflow_id, callback_reviewer, callback_comments


def _authorizer_tenant_id(event: IngressEvent) -> str:
    tenant_id = str(getattr(event, "tenant_id", "") or "").strip()
    if tenant_id and tenant_id.lower() != "unknown":
        return tenant_id

    # Graph notification route is intentionally unauthenticated at API Gateway level.
    # Fall back to path parameters when authorizer context is not present.
    path_tenant_id = str((getattr(event, "path_params", {}) or {}).get("tenant_id", "") or "").strip()
    return path_tenant_id


# -- Route: /api/v1/hitl/respond -----------------------------------------------

async def handle_hitl_respond(event: IngressEvent) -> dict:
    token, action, callback_workflow_id, callback_reviewer, callback_comments = _extract_hitl_callback_fields(event)

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
        update_result = _get_dynamo_client().update_item(
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

    if callback_workflow_id and callback_workflow_id != workflow_id:
        logger.warning(
            "HiTL respond rejected token=%s workflow_id_mismatch callback=%s token_record=%s",
            token_preview,
            callback_workflow_id,
            workflow_id,
        )
        return _html_response(
            403,
            "<html><body><h3>Forbidden</h3><p>Workflow identity mismatch for this approval token.</p></body></html>",
        )

    reviewer = f"email:{reviewer_email}"
    if callback_reviewer:
        reviewer = callback_reviewer if ":" in callback_reviewer else f"teams:{callback_reviewer}"

    payload = {
        "approved": str(action) != "dismiss",
        "reviewer": reviewer,
        "action": str(action),
        "comments": callback_comments or "Approved via signed email link",
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


# -- Route: /api/v1/hitl/jira/{tenant_id} --------------------------------------

async def handle_hitl_jira(event: IngressEvent) -> dict:
    body = event.body or {}
    tenant_id = _authorizer_tenant_id(event)
    if not tenant_id:
        return response.error(401, "Missing verified tenant context")

    signature = _find_header(event.headers, "x-hub-signature-256")
    if not signature:
        return response.error(401, "Missing x-hub-signature-256")

    secret_path = f"/secamo/tenants/{tenant_id}/hitl/jira_webhook_secret"
    try:
        secret_resp = _get_ssm_client().get_parameter(Name=secret_path, WithDecryption=True)
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


# -- Route: /api/v1/ingress/internal -------------------------------------------

async def handle_internal(event: IngressEvent) -> dict:
    if not isinstance(event.body, dict):
        return response.error(400, "Request body must be a JSON object")

    tenant_id = _authorizer_tenant_id(event)
    if not tenant_id:
        return response.error(401, "Missing verified tenant context")

    try:
        iam_request = IamIngressRequest.model_validate(event.body)
    except Exception as exc:
        return response.error(400, f"Invalid IAM request body: {exc}")

    outcome = await _get_ingress_pipeline().dispatch_provider_event(
        raw_body=iam_request.model_dump(mode="json"),
        provider="microsoft_graph",
        event_type="iam_request",
        tenant_id=tenant_id,
        authenticate=False,
    )
    if not outcome.accepted:
        return response.error(outcome.status_code, outcome.error_message or "internal pipeline failure")

    return response.accepted(
        {
            "tenant_id": outcome.tenant_id,
            "provider": outcome.provider,
            "event_type": outcome.event_type,
            "attempted": outcome.attempted,
            "succeeded": outcome.succeeded,
            "failed": outcome.failed,
        }
    )


async def handle_event(event: IngressEvent) -> dict:
    """Generic provider-event ingress route for workflow starts."""

    if not isinstance(event.body, dict):
        return response.error(400, "Request body must be a JSON object")

    tenant_id = _authorizer_tenant_id(event)
    if not tenant_id:
        return response.error(401, "Missing verified tenant context")

    provider = str(event.body.get("provider", "")).strip().lower()
    if not provider:
        return response.error(400, "provider is required in request body")

    event_type = str(event.body.get("event_type", "alert")).strip().lower() or "alert"
    outcome = await _get_ingress_pipeline().dispatch_provider_event(
        raw_body=dict(event.body),
        provider=provider,
        event_type=event_type,
        tenant_id=tenant_id,
        headers={str(k): str(v) for k, v in (event.headers or {}).items()},
        raw_body_text=event.raw_body or "",
        channel="webhook",
        authenticate=True,
    )
    if not outcome.accepted:
        return response.error(outcome.status_code, outcome.error_message or "provider event rejected")

    return response.accepted(
        {
            "tenant_id": outcome.tenant_id,
            "provider": outcome.provider,
            "event_type": outcome.event_type,
            "attempted": outcome.attempted,
            "succeeded": outcome.succeeded,
            "failed": outcome.failed,
        }
    )


async def handle_graph_notification(event: IngressEvent) -> dict:
    # Handle Microsoft Graph subscription validation before any auth check.
    # Microsoft sends an unauthenticated POST with ?validationToken=... and expects
    # HTTP 200 plain-text echo within 10 seconds (no credentials are provided).
    validation_token = str((event.query_params or {}).get("validationToken", "")).strip()
    if validation_token:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": validation_token,
        }

    tenant_id = _authorizer_tenant_id(event)
    if not tenant_id:
        return response.error(401, "Missing verified tenant context")

    if not isinstance(event.body, dict):
        return response.error(400, "Request body must be a JSON object")

    outcome = await _get_ingress_pipeline().dispatch_graph_notifications(
        tenant_id=tenant_id,
        body=event.body,
        headers={str(k): str(v) for k, v in (event.headers or {}).items()},
        raw_body_text=event.raw_body or "",
    )
    if not outcome.accepted:
        return response.error(outcome.status_code, outcome.error_message or "graph notification rejected")

    return response.accepted(
        {
            "tenant_id": tenant_id,
            "provider": "microsoft_graph",
            "received": outcome.received,
            "dispatched": outcome.dispatched,
            "ignored": outcome.ignored,
        }
    )


# -- Lambda Entrypoint ----------------------------------------------------------

handler = async_handler(
    {
        "/api/v1/ingress/event/{tenant_id}": handle_event,
        "/api/v1/ingress/internal": handle_internal,
        "/api/v1/graph/notifications/{tenant_id}": handle_graph_notification,
        "/api/v1/hitl/respond": handle_hitl_respond,
        "/api/v1/hitl/jira/{tenant_id}": handle_hitl_jira,
    }
)
