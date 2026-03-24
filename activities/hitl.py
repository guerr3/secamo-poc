from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from urllib.parse import urlencode
from urllib.parse import quote

import boto3
import httpx
from botocore.exceptions import ClientError
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._activity_errors import application_error_from_http_status, raise_activity_error
from shared.config import SECAMO_SENDER_EMAIL
from shared.graph_client import get_graph_token
from shared.models import HiTLRequest, TenantSecrets
from activities.hitl_renderers import _render_approval_email


class _LazyBotoClient:
    def __init__(self, service_name: str, region_name: str) -> None:
        self._service_name = service_name
        self._region_name = region_name
        self._client = None

    def _get_client(self):
        if self._client is None:
            self._client = boto3.client(self._service_name, region_name=self._region_name)
        return self._client

    def __getattr__(self, name: str):
        return getattr(self._get_client(), name)


_ssm = _LazyBotoClient("ssm", "eu-west-1")
_dynamo = _LazyBotoClient("dynamodb", "eu-west-1")


def _token_table_name() -> str:
    table_name = os.environ.get("HITL_TOKEN_TABLE", "").strip()
    if not table_name:
        raise ValueError("HITL_TOKEN_TABLE is not configured")
    return table_name


def _name_prefix() -> str:
    return os.environ.get("HITL_NAME_PREFIX", "secamo-temporal-test").strip() or "secamo-temporal-test"


def _join_query_url(base_url: str, token: str, action: str) -> str:
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}{urlencode({'token': token, 'action': action})}"


def _put_token_record(request: HiTLRequest, token: str) -> None:
    expires_at = int(time.time()) + int(request.timeout_hours * 3600)
    _dynamo.put_item(
        TableName=_token_table_name(),
        Item={
            "token": {"S": token},
            "workflow_id": {"S": request.workflow_id},
            "tenant_id": {"S": request.tenant_id},
            "reviewer_email": {"S": request.reviewer_email},
            "allowed_actions": {"SS": sorted(set(request.allowed_actions))},
            "used": {"BOOL": False},
            "channel": {"S": "email"},
            "expires_at": {"N": str(expires_at)},
        },
        ConditionExpression="attribute_not_exists(token)",
    )


def _deterministic_token(request: HiTLRequest) -> str:
    """Build a stable token per activity execution identity for retry safety."""
    info = activity.info()
    raw = (
        f"{request.workflow_id}:{request.tenant_id}:"
        f"{info.workflow_run_id}:{info.activity_id}"
    ).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    # 43 chars URL-safe token from 32-byte digest (without padding).
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


async def _dispatch_email(request: HiTLRequest, graph_secrets: TenantSecrets) -> str:
    token = _deterministic_token(request)
    try:
        _put_token_record(request, token)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "ConditionalCheckFailedException":
            raise

    parameter_name = f"/{_name_prefix()}/hitl/endpoint_base_url"
    endpoint = _ssm.get_parameter(Name=parameter_name, WithDecryption=False)
    base_url = endpoint.get("Parameter", {}).get("Value", "").strip()
    if not base_url:
        raise_activity_error(
            f"Empty HiTL endpoint base URL in SSM parameter: {parameter_name}",
            error_type="MissingHitlEndpointConfig",
            non_retryable=True,
        )

    action_urls = {
        action: _join_query_url(base_url, token, action)
        for action in request.allowed_actions
    }

    email_html = _render_approval_email(request, action_urls)
    graph_token = await get_graph_token(graph_secrets)

    payload = {
        "message": {
            "subject": f"[Secamo Approval] {request.title}",
            "body": {
                "contentType": "HTML",
                "content": email_html,
            },
            "toRecipients": [{"emailAddress": {"address": request.reviewer_email}}],
        },
        "saveToSentItems": "false",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"https://graph.microsoft.com/v1.0/users/{quote(SECAMO_SENDER_EMAIL)}/sendMail",
            headers={
                "Authorization": f"Bearer {graph_token}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if response.status_code >= 400:
        retry_after_seconds: int | None = None
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                retry_after_seconds = int(retry_after)
            except ValueError:
                retry_after_seconds = None
        raise application_error_from_http_status(
            request.tenant_id,
            "microsoft_graph",
            "hitl_dispatch_email",
            response.status_code,
            retry_after_seconds=retry_after_seconds,
        )

    activity.logger.info(
        "[%s] HiTL email dispatched token=%s... recipient=%s",
        request.tenant_id,
        token[:8],
        request.reviewer_email,
    )
    return token


async def _dispatch_jira(request: HiTLRequest, jira_secrets: TenantSecrets | None) -> str:
    if not request.ticket_key:
        activity.logger.warning("[%s] Jira dispatch skipped: request.ticket_key is not set", request.tenant_id)
        return "skipped:no_ticket_key"

    if jira_secrets is None:
        activity.logger.warning("[%s] Jira dispatch skipped: jira_secrets missing", request.tenant_id)
        return "skipped:no_jira_secrets"

    if not jira_secrets.jira_base_url or not jira_secrets.jira_email or not jira_secrets.jira_api_token:
        activity.logger.warning("[%s] Jira dispatch skipped: incomplete Jira secrets", request.tenant_id)
        return "skipped:incomplete_jira_secrets"

    base_url = jira_secrets.jira_base_url.rstrip("/")
    auth = (jira_secrets.jira_email, jira_secrets.jira_api_token)
    transition_id = str(request.metadata.get("jsm_approval_transition_id", "31"))
    workflow_label = f"secamo-wf:{request.workflow_id}"

    async with httpx.AsyncClient(timeout=30.0, auth=auth) as client:
        labels_response = await client.put(
            f"{base_url}/rest/api/3/issue/{request.ticket_key}",
            json={
                "update": {
                    "labels": [
                        {"add": workflow_label},
                    ]
                }
            },
        )
        if labels_response.status_code >= 400:
            raise application_error_from_http_status(
                request.tenant_id,
                "jira",
                "hitl_dispatch_jira_add_label",
                labels_response.status_code,
            )

        transition_response = await client.post(
            f"{base_url}/rest/api/3/issue/{request.ticket_key}/transitions",
            json={"transition": {"id": transition_id}},
        )
        if transition_response.status_code >= 400:
            raise application_error_from_http_status(
                request.tenant_id,
                "jira",
                "hitl_dispatch_jira_transition",
                transition_response.status_code,
            )

    activity.logger.info(
        "[%s] Jira HiTL dispatch completed ticket=%s transition_id=%s",
        request.tenant_id,
        request.ticket_key,
        transition_id,
    )
    return request.ticket_key


@activity.defn
async def request_hitl_approval(
    tenant_id: str,
    request: HiTLRequest,
    graph_secrets: TenantSecrets,
    jira_secrets: TenantSecrets | None = None,
) -> str:
    activity.logger.info(
        "[%s] request_hitl_approval workflow_id=%s channels=%s",
        tenant_id,
        request.workflow_id,
        request.channels,
    )

    dispatch_results: dict[str, str] = {}

    dispatch_map = {
        "email": lambda: _dispatch_email(request, graph_secrets),
        "jira": lambda: _dispatch_jira(request, jira_secrets),
    }

    for channel in request.channels:
        activity.heartbeat({"channel": channel, "dispatch_results": dispatch_results})
        handler = dispatch_map.get(channel)
        if handler is None:
            activity.logger.warning("[%s] HiTL channel '%s' is not supported", tenant_id, channel)
            dispatch_results[channel] = "skipped:unsupported"
            continue

        try:
            await handler()
            dispatch_results[channel] = "ok"
        except ApplicationError as exc:
            dispatch_results[channel] = f"error:{exc.type}"
            activity.logger.error(
                "[%s] HiTL channel '%s' dispatch failed error=%s",
                tenant_id,
                channel,
                exc.type,
            )
        except Exception as exc:
            dispatch_results[channel] = f"error:{type(exc).__name__}"
            activity.logger.error(
                "[%s] HiTL channel '%s' dispatch failed error=%s",
                tenant_id,
                channel,
                type(exc).__name__,
            )

    successful_channels = sum(1 for status in dispatch_results.values() if status == "ok")
    failed_channels = [channel for channel, status in dispatch_results.items() if status.startswith("error:")]
    if successful_channels == 0 and failed_channels:
        raise_activity_error(
            f"[{tenant_id}] HiTL dispatch failed for channels={','.join(failed_channels)}",
            error_type="HiTLDispatchFailed",
            non_retryable=False,
        )

    return json.dumps(dispatch_results)
