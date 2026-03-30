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
from datetime import datetime, timezone
from uuid import uuid4

import boto3
import jwt
from botocore.exceptions import ClientError

from ingress_sdk import temporal, response
from ingress_sdk.dispatch import async_handler
from ingress_sdk.event import IngressEvent

from shared.models import GraphNotificationEnvelope, IamIngressRequest
from shared.models.canonical import (
    Correlation,
    Envelope,
    SecamoEventVariantAdapter,
    StoragePartition,
    VendorExtension,
    derive_event_id,
)
from shared.models.mappers import resolve_provider_event_route
from shared.routing import build_default_route_registry
from shared.temporal.dispatcher import RouteFanoutDispatcher, WorkflowStarter
from shared.auth import AuthValidationRequest, CachedSecretResolver, build_default_validator_registry
from mappers import normalize_event_body


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
    validation = await _get_auth_registry().validate(
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
        envelope = _build_envelope(
            raw_body=iam_request.model_dump(mode="json"),
            normalized=normalized,
            provider="microsoft_graph",
            tenant_id=event.tenant_id,
            event_type="iam.onboarding",
        )
    except Exception as exc:
        return response.error(400, f"Normalized IAM payload failed Envelope validation: {exc}")

    # 2. Start workflow via ingress_sdk with strict Envelope payload shape.
    result = await temporal.start_workflow(
        workflow="IamOnboardingWorkflow",
        input=envelope.model_dump(mode="json"),
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


def _severity_to_id(severity: str | None) -> int:
    mapping = {
        "informational": 10,
        "low": 20,
        "medium": 40,
        "high": 60,
        "critical": 80,
    }
    return mapping.get(str(severity or "").strip().lower(), 40)


def _parse_occurred_at(raw_body: dict) -> datetime:
    raw_value = raw_body.get("occurred_at") or raw_body.get("timestamp")
    if isinstance(raw_value, str):
        candidate = raw_value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _build_storage_partition(*, tenant_id: str, event_type: str, provider_event_id: str) -> StoragePartition:
    event_key = event_type.replace(".", "#")
    return StoragePartition(
        ddb_pk=f"TENANT#{tenant_id}",
        ddb_sk=f"EVENT#{event_key}#{provider_event_id}",
        s3_bucket=f"secamo-events-{tenant_id}",
        s3_key_prefix=f"raw/{event_type}/{provider_event_id}",
    )


def _build_envelope(
    *,
    raw_body: dict,
    normalized: dict,
    provider: str,
    tenant_id: str,
    event_type: str,
) -> Envelope:
    provider_event_id = str(normalized.get("event_id") or raw_body.get("event_id") or uuid4())
    occurred_at = _parse_occurred_at(raw_body)
    correlation_id = str(normalized.get("correlation_id") or raw_body.get("correlation_id") or provider_event_id)
    request_id = str(raw_body.get("request_id") or correlation_id)
    event_key = str(event_type).strip().lower()

    payload_candidate: dict
    if event_key == "defender.alert":
        alert = normalized.get("alert") if isinstance(normalized.get("alert"), dict) else {}
        severity = str(alert.get("severity") or normalized.get("severity") or "medium").lower()
        payload_candidate = {
            "event_type": "defender.alert",
            "activity_id": 2004,
            "activity_name": "alert_detected",
            "alert_id": str(alert.get("alert_id") or provider_event_id),
            "title": str(alert.get("title") or "Security alert"),
            "description": str(alert.get("description") or ""),
            "severity_id": _severity_to_id(severity),
            "severity": severity,
            "status": str(alert.get("status") or "open"),
            "vendor_extensions": {
                "source_ip": VendorExtension(source="ingress", value=alert.get("source_ip")),
                "destination_ip": VendorExtension(source="ingress", value=alert.get("destination_ip")),
                "device_id": VendorExtension(source="ingress", value=alert.get("device_id")),
                "user_email": VendorExtension(source="ingress", value=alert.get("user_email")),
            },
        }
    elif event_key == "defender.impossible_travel":
        user = normalized.get("user") if isinstance(normalized.get("user"), dict) else {}
        network = normalized.get("network") if isinstance(normalized.get("network"), dict) else {}
        severity = str(normalized.get("severity") or "high").lower()
        payload_candidate = {
            "event_type": "defender.impossible_travel",
            "activity_id": 3002,
            "activity_name": "impossible_travel",
            "user_principal_name": str(user.get("user_principal_name") or "unknown@example.com"),
            "source_ip": str(network.get("source_ip") or "0.0.0.0"),
            "destination_ip": (str(network.get("destination_ip")) if network.get("destination_ip") else None),
            "severity_id": _severity_to_id(severity),
            "severity": severity,
        }
    elif event_key == "iam.onboarding":
        user = normalized.get("user") if isinstance(normalized.get("user"), dict) else {}
        action = str(user.get("action") or "create").lower()
        activity_map = {"create": 1, "update": 2, "delete": 3, "password_reset": 4}
        payload_candidate = {
            "event_type": "iam.onboarding",
            "activity_id": activity_map.get(action, 1),
            "activity_name": action,
            "user_email": str(user.get("user_principal_name") or "unknown@example.com"),
            "action": action,
            "user_data": user.get("user_data") if isinstance(user.get("user_data"), dict) else {},
        }
    elif event_key == "hitl.approval":
        payload_candidate = {
            "event_type": "hitl.approval",
            "activity_id": 9001,
            "activity_name": "hitl_response",
            "approval_id": str(raw_body.get("approval_id") or provider_event_id),
            "decision": str(raw_body.get("decision") or "approved"),
            "channel": str(raw_body.get("channel") or "web"),
            "responder": (str(raw_body.get("responder")) if raw_body.get("responder") else None),
            "reason": (str(raw_body.get("reason")) if raw_body.get("reason") else None),
        }
    else:
        raise ValueError(f"unsupported_event_type:{event_key}")

    payload = SecamoEventVariantAdapter.validate_python(payload_candidate)

    event_id = derive_event_id(
        tenant_id=tenant_id,
        event_type=payload.event_type,
        occurred_at=occurred_at,
        correlation_id=correlation_id,
        provider_event_id=provider_event_id,
    )
    correlation = Correlation(
        correlation_id=correlation_id,
        causation_id=correlation_id,
        request_id=request_id,
        trace_id=correlation_id,
        storage_partition=_build_storage_partition(
            tenant_id=tenant_id,
            event_type=payload.event_type,
            provider_event_id=provider_event_id,
        ),
    )

    return Envelope(
        event_id=event_id,
        tenant_id=tenant_id,
        source_provider=provider,
        event_name=payload.event_type,
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=occurred_at,
        correlation=correlation,
        payload=payload,
        metadata={
            "provider_event_id": provider_event_id,
            "requester": normalized.get("requester"),
            "ticket_id": normalized.get("ticket_id"),
        },
    )


async def _dispatch_provider_event(*, raw_body: dict, provider: str, event_type: str, tenant_id: str) -> dict:
    routing = resolve_provider_event_route(provider, event_type)
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
    canonical_event_type = str(normalized.get("event_type") or event_type).strip().lower()

    try:
        envelope = _build_envelope(
            raw_body=raw_body,
            normalized=normalized,
            provider=provider,
            tenant_id=tenant_id,
            event_type=canonical_event_type,
        )
    except Exception as exc:
        return response.error(400, f"Normalized ingress payload failed Envelope validation: {exc}")

    fanout_report = await _route_fanout_dispatcher.dispatch_intent(envelope)
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
