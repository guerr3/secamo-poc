"""
Proxy Lambda — Front Door Ingress (Temporal Client)

Routes:
    POST /api/v1/ingress/event/{tenant_id} → Start routed provider workflow
    POST /api/v1/ingress/internal          → Start internal first-party workflow
    GET  /api/v1/hitl/respond    → Consume signed email approval token
    POST /api/v1/hitl/jira       → Consume Jira webhook approval callback

All infrastructure (Temporal client, event parsing, response formatting,
async dispatch) is provided by the ingress_sdk Lambda Layer.

Responsibility: route ingress requests to Temporal workflows through shared normalization/routing boundaries.
This module must not contain workflow business logic or activity implementations.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from urllib.request import urlopen

import boto3
import jwt
from botocore.exceptions import ClientError

from ingress_sdk import temporal, response
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

from shared.models import CanonicalEvent, IamIngressRequest, SecurityEvent
from shared.normalization.normalizers import canonical_event_to_workflow_intent
from shared.routing import build_default_route_registry
from shared.temporal.dispatcher import RouteFanoutDispatcher, WorkflowStarter
from mappers import normalize_event_body


_dynamo = boto3.client("dynamodb", region_name="eu-west-1")
_ssm = boto3.client("ssm", region_name="eu-west-1")
logger = logging.getLogger("ingress.hitl")


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


def _ssm_get_parameter_value(name: str) -> str:
    try:
        response = _ssm.get_parameter(Name=name, WithDecryption=True)
        return str(response.get("Parameter", {}).get("Value", ""))
    except ClientError:
        return ""


def _validate_hmac_sha256(*, signature: str, secret: str, raw_body: str) -> bool:
    if not signature or not secret:
        return False
    expected = hmac.new(
        secret.encode("utf-8"),
        (raw_body or "").encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    supplied = str(signature).strip()
    if supplied.lower().startswith("sha256="):
        supplied = supplied.split("=", 1)[1]
    return hmac.compare_digest(supplied, expected)


def _validate_microsoft_defender_signature(event: IngressEvent, tenant_id: str) -> bool:
    auth_header = _find_header(event.headers, "authorization")
    if not auth_header.lower().startswith("bearer "):
        return False

    token = auth_header[7:].strip()
    if not token:
        return False

    tenant_azure_id = _ssm_get_parameter_value(f"/secamo/tenants/{tenant_id}/graph/tenant_azure_id")
    if not tenant_azure_id:
        return False

    jwks_url = f"https://login.microsoftonline.com/{tenant_azure_id}/discovery/v2.0/keys"
    try:
        with urlopen(jwks_url, timeout=5) as jwks_resp:
            if jwks_resp.status != 200:
                return False
            json.loads(jwks_resp.read().decode("utf-8"))

        jwk_client = jwt.PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience="https://management.azure.com/",
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except Exception:
        return False

    issuer = str(claims.get("iss", ""))
    allowed_issuers = {
        f"https://login.microsoftonline.com/{tenant_azure_id}/v2.0",
        f"https://sts.windows.net/{tenant_azure_id}/",
    }
    return issuer in allowed_issuers


def _validate_crowdstrike_signature(event: IngressEvent, tenant_id: str) -> bool:
    signature = _find_header(event.headers, "x-cs-signature")
    secret = _ssm_get_parameter_value(f"/secamo/tenants/{tenant_id}/webhooks/crowdstrike_secret")
    return _validate_hmac_sha256(signature=signature, secret=secret, raw_body=event.raw_body or "")


def _validate_sentinelone_signature(event: IngressEvent, tenant_id: str) -> bool:
    signature = _find_header(event.headers, "x-sentinel-one-signature")
    secret = _ssm_get_parameter_value(f"/secamo/tenants/{tenant_id}/webhooks/sentinelone_secret")
    return _validate_hmac_sha256(signature=signature, secret=secret, raw_body=event.raw_body or "")


def _validate_jira_ingress_signature(event: IngressEvent, tenant_id: str) -> bool:
    signature = _find_header(event.headers, "x-hub-signature-256")
    secret = _ssm_get_parameter_value(f"/secamo/tenants/{tenant_id}/webhooks/jira_secret")
    return _validate_hmac_sha256(signature=signature, secret=secret, raw_body=event.raw_body or "")


_SIGNATURE_VALIDATORS = {
    "microsoft_defender": _validate_microsoft_defender_signature,
    "crowdstrike": _validate_crowdstrike_signature,
    "sentinelone": _validate_sentinelone_signature,
    "jira": _validate_jira_ingress_signature,
}


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


async def handle_event(event: IngressEvent) -> dict:
    """Generic provider-event ingress route for workflow starts."""
    tenant_id = str((event.path_params or {}).get("tenant_id", "")).strip()
    if not tenant_id:
        return response.error(400, "tenant_id path parameter is required")

    provider = str(event.body.get("provider", "")).strip().lower()
    if not provider:
        return response.error(400, "provider is required in request body")

    validator = _SIGNATURE_VALIDATORS.get(provider)
    if validator is None:
        logger.warning("No signature validator configured for provider=%s; allowing request", provider)
    elif not validator(event, tenant_id):
        return response.error(401, "Invalid provider signature")

    event_type = str(event.body.get("event_type", "alert")).strip().lower() or "alert"
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
        raw_body=event.body,
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
        payload=dict(event.body),
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


# ── Lambda Entrypoint ────────────────────────────────────────

handler = async_handler({
    "/api/v1/ingress/event/{tenant_id}": handle_event,
    "/api/v1/ingress/internal": handle_internal,
    "/api/v1/hitl/respond": handle_hitl_respond,
    "/api/v1/hitl/jira": handle_hitl_jira,
})
