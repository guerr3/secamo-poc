"""
Proxy Lambda — Front Door Ingress (Temporal Client)

Routes:
    POST /api/v1/ingress/event/{tenant_id} → Start routed provider workflow
    POST /api/v1/ingress/internal          → Start internal first-party workflow
    GET  /api/v1/hitl/respond    → Consume signed email approval token
    POST /api/v1/hitl/jira/{tenant_id} → Consume Jira webhook approval callback

All infrastructure (Temporal client, event parsing, response formatting,
async dispatch) is provided by the ingress_sdk Lambda Layer.

Responsibility: route ingress requests to Temporal workflows through shared normalization/routing boundaries.
This module must not contain workflow business logic or activity implementations.
"""

import hashlib
import hmac
import logging
import os
import time
from uuid import uuid4

import boto3
import jwt
from botocore.exceptions import ClientError

from ingress_sdk import temporal, response
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

from shared.models import CanonicalEvent, GraphNotificationEnvelope, IamIngressRequest, SecurityEvent
from shared.normalization.normalizers import canonical_event_to_workflow_intent
from shared.routing import build_default_route_registry
from shared.temporal.dispatcher import RouteFanoutDispatcher, WorkflowStarter
from shared.auth import AuthValidationRequest, CachedSecretResolver, build_default_validator_registry
from mappers import normalize_event_body


_dynamo = boto3.client("dynamodb", region_name="eu-west-1")
_ssm = boto3.client("ssm", region_name="eu-west-1")
logger = logging.getLogger("ingress.hitl")

GRAPH_NOTIFICATION_AZP = "0bf30f3b-4a52-48df-9a82-234910c4a086"
GRAPH_COMMON_JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
GRAPH_NOTIFICATION_APP_IDS = {
    value.strip() for value in os.environ.get("GRAPH_NOTIFICATION_APP_IDS", "").split(",") if value.strip()
}
_graph_jwks_client = jwt.PyJWKClient(GRAPH_COMMON_JWKS_URL)
_auth_resolver = CachedSecretResolver()
_auth_registry = build_default_validator_registry(_auth_resolver)


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
    """Extract callback token/action/identity fields from GET query or POST body.

    Returns:
        token, action, callback_workflow_id, callback_reviewer, callback_comments
    """
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
    if not tenant_id or tenant_id.lower() == "unknown":
        return ""
    return tenant_id


async def _validate_provider_authentication(*, event: IngressEvent, tenant_id: str, provider: str, channel: str = "webhook") -> bool:
    validation = await _auth_registry.validate(
        AuthValidationRequest(
            tenant_id=tenant_id,
            provider=provider,
            channel=channel,
            headers={str(k): str(v) for k, v in (event.headers or {}).items()},
            raw_body=event.raw_body or "",
        )
    )
    if validation.authenticated:
        return True

    logger.warning(
        "Provider authentication failed tenant_id=%s provider=%s channel=%s reason=%s details=%s",
        tenant_id,
        provider,
        channel,
        validation.reason,
        validation.details,
    )
    return False


PROVIDER_EVENT_ROUTING = {
    ("microsoft_defender", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_defender", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("crowdstrike", "detection_summary"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("crowdstrike", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("sentinelone", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("jira", "jira:issue_created"): ("IamOnboardingWorkflow", "iam-graph"),
    ("jira", "jira:issue_updated"): ("IamOnboardingWorkflow", "iam-graph"),
}


# ── Route: /api/v1/hitl/respond ─────────────────────────────

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


# ── Route: /api/v1/hitl/jira/{tenant_id} ───────────────────

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


# ── Route: /api/v1/ingress/internal ───────────────────────────────

async def handle_internal(event: IngressEvent) -> dict:
    """Validate an internal request and start an IamOnboardingWorkflow."""

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

    try:
        security_event = SecurityEvent.model_validate(normalized)
    except Exception as exc:
        return response.error(400, f"Normalized IAM payload failed SecurityEvent validation: {exc}")

    # 2. Start workflow via ingress_sdk with universal SecurityEvent payload shape.
    result = await temporal.start_workflow(
        workflow="IamOnboardingWorkflow",
        input=security_event.model_dump(mode="json"),
        tenant_id=event.tenant_id,
        task_queue="iam-graph",
    )
    return response.accepted(result)


def _validate_graph_validation_tokens(tokens: list[str] | None) -> bool:
    if not tokens:
        return True

    if not GRAPH_NOTIFICATION_APP_IDS:
        return False

    for token in tokens:
        try:
            signing_key = _graph_jwks_client.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=list(GRAPH_NOTIFICATION_APP_IDS),
                options={"require": ["exp", "iat", "iss", "aud", "azp"]},
            )
        except Exception:
            return False

        issuer = str(claims.get("iss") or "")
        if not issuer.startswith("https://login.microsoftonline.com/"):
            return False
        if str(claims.get("azp") or "") != GRAPH_NOTIFICATION_AZP:
            return False

    return True


def _graph_event_type_from_resource(resource: str) -> str:
    value = str(resource or "").strip().lower()
    if "alerts" in value:
        return "alert"
    if "signin" in value or "risky" in value:
        return "impossible_travel"
    return ""


def _graph_client_state_matches_tenant(client_state: str | None, tenant_id: str) -> bool:
    if not client_state:
        return True
    expected_prefix = f"secamo:{tenant_id}:"
    return str(client_state).startswith(expected_prefix)


def _graph_item_to_provider_payload(item: dict, event_type: str) -> dict:
    resource_data = item.get("resourceData") if isinstance(item.get("resourceData"), dict) else {}
    alert_id = str(resource_data.get("id") or item.get("subscriptionId") or str(uuid4()))

    return {
        "event_type": event_type,
        "alert": {
            "id": alert_id,
            "severity": str(resource_data.get("severity") or "medium").lower(),
            "title": str(resource_data.get("title") or resource_data.get("riskEventType") or "Graph notification"),
            "description": str(resource_data.get("description") or resource_data.get("riskDetail") or ""),
            "deviceId": resource_data.get("deviceId") or resource_data.get("azureAdDeviceId"),
            "userPrincipalName": resource_data.get("userPrincipalName") or resource_data.get("accountName"),
            "ipAddress": resource_data.get("ipAddress"),
            "destinationIp": resource_data.get("destinationIp"),
        },
        "resource": item.get("resource"),
        "change_type": item.get("changeType"),
        "subscription_id": item.get("subscriptionId"),
        "client_state": item.get("clientState"),
    }


async def _dispatch_provider_event(*, raw_body: dict, provider: str, event_type: str, tenant_id: str) -> dict:
    routing = PROVIDER_EVENT_ROUTING.get((provider, event_type))
    if routing is None:
        return response.error(
            400,
            f"No workflow mapping found for provider='{provider}' event_type='{event_type}'",
        )

    normalized = normalize_event_body(
        provider=provider,
        event_type=event_type,
        tenant_id=tenant_id,
        raw_body=raw_body,
    )

    try:
        security_event = SecurityEvent.model_validate(normalized)
    except Exception as exc:
        return response.error(400, f"Normalized ingress payload failed SecurityEvent validation: {exc}")

    canonical_event = CanonicalEvent(
        event_type=security_event.event_type,
        tenant_id=tenant_id,
        provider=provider,
        external_event_id=security_event.event_id,
        subject=(security_event.alert.title if security_event.alert else "ingress event"),
        severity=security_event.severity,
        payload=dict(raw_body),
        request_id=security_event.correlation_id,
    )
    workflow_input = security_event.model_dump(mode="json")
    intent = canonical_event_to_workflow_intent(canonical_event, workflow_input=workflow_input)

    fanout_report = await _route_fanout_dispatcher.dispatch_intent(intent)
    return response.accepted(
        {
            "tenant_id": tenant_id,
            "provider": provider,
            "event_type": event_type,
            "attempted": fanout_report.attempted,
            "succeeded": fanout_report.succeeded,
            "failed": fanout_report.failed,
        }
    )


async def handle_event(event: IngressEvent) -> dict:
    """Generic provider-event ingress route for workflow starts."""
    tenant_id = _authorizer_tenant_id(event)
    if not tenant_id:
        return response.error(401, "Missing verified tenant context")

    provider = str(event.body.get("provider", "")).strip().lower()
    if not provider:
        return response.error(400, "provider is required in request body")

    if not await _validate_provider_authentication(event=event, tenant_id=tenant_id, provider=provider, channel="webhook"):
        return response.error(401, "Invalid provider signature")

    event_type = str(event.body.get("event_type", "alert")).strip().lower() or "alert"
    return await _dispatch_provider_event(
        raw_body=dict(event.body),
        provider=provider,
        event_type=event_type,
        tenant_id=tenant_id,
    )


async def handle_graph_notification(event: IngressEvent) -> dict:
    tenant_id = _authorizer_tenant_id(event)
    if not tenant_id:
        return response.error(401, "Missing verified tenant context")

    validation_token = str((event.query_params or {}).get("validationToken", "")).strip()
    if validation_token:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/plain"},
            "body": validation_token,
        }

    if not await _validate_provider_authentication(
        event=event,
        tenant_id=tenant_id,
        provider="microsoft_defender",
        channel="webhook",
    ):
        return response.error(401, "Invalid provider signature")

    if not isinstance(event.body, dict):
        return response.error(400, "Request body must be a JSON object")

    try:
        envelope = GraphNotificationEnvelope.model_validate(event.body)
    except Exception as exc:
        return response.error(400, f"Invalid Graph notification payload: {exc}")

    if not _validate_graph_validation_tokens(envelope.validationTokens):
        return response.error(401, "Invalid Graph validation tokens")

    dispatched = 0
    ignored = 0
    for item in envelope.value:
        if not _graph_client_state_matches_tenant(item.clientState, tenant_id):
            ignored += 1
            continue

        event_type = _graph_event_type_from_resource(item.resource)
        if not event_type:
            ignored += 1
            continue

        provider_payload = _graph_item_to_provider_payload(item.model_dump(mode="json"), event_type)
        dispatch_result = await _dispatch_provider_event(
            raw_body=provider_payload,
            provider="microsoft_defender",
            event_type=event_type,
            tenant_id=tenant_id,
        )
        if int(dispatch_result.get("statusCode", 500)) >= 400:
            return dispatch_result
        dispatched += 1

    return response.accepted(
        {
            "tenant_id": tenant_id,
            "provider": "microsoft_defender",
            "received": len(envelope.value),
            "dispatched": dispatched,
            "ignored": ignored,
        }
    )


# ── Lambda Entrypoint ────────────────────────────────────────

handler = async_handler({
    "/api/v1/ingress/event/{tenant_id}": handle_event,
    "/api/v1/ingress/internal": handle_internal,
    "/api/v1/graph/notifications/{tenant_id}": handle_graph_notification,
    "/api/v1/hitl/respond": handle_hitl_respond,
    "/api/v1/hitl/jira/{tenant_id}": handle_hitl_jira,
})
