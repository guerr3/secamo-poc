from __future__ import annotations

import json
import os
import secrets
import time
from urllib.parse import urlencode

import boto3
import httpx
from botocore.exceptions import ClientError
from temporalio import activity

from shared.config import SECAMO_SENDER_EMAIL
from shared.graph_client import get_graph_token
from shared.models import HiTLRequest, TenantSecrets
from activities.hitl_renderers import _render_approval_email

_ssm = boto3.client("ssm", region_name="eu-west-1")
_dynamo = boto3.client("dynamodb", region_name="eu-west-1")


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


async def _dispatch_email(request: HiTLRequest, graph_secrets: TenantSecrets) -> str:
    token = ""
    for _ in range(3):
        token = secrets.token_urlsafe(32)
        try:
            _put_token_record(request, token)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ConditionalCheckFailedException":
                raise
    else:
        raise RuntimeError("Unable to generate a unique HiTL token")

    parameter_name = f"/{_name_prefix()}/hitl/endpoint_base_url"
    endpoint = _ssm.get_parameter(Name=parameter_name, WithDecryption=False)
    base_url = endpoint.get("Parameter", {}).get("Value", "").strip()
    if not base_url:
        raise ValueError(f"Empty HiTL endpoint base URL in SSM parameter: {parameter_name}")

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
            f"https://graph.microsoft.com/v1.0/users/{SECAMO_SENDER_EMAIL}/sendMail",
            headers={
                "Authorization": f"Bearer {graph_token}",
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if response.status_code >= 400:
        raise RuntimeError(f"Graph email_send failed with status={response.status_code}")

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
        labels_response.raise_for_status()

        transition_response = await client.post(
            f"{base_url}/rest/api/3/issue/{request.ticket_key}/transitions",
            json={"transition": {"id": transition_id}},
        )
        transition_response.raise_for_status()

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
        handler = dispatch_map.get(channel)
        if handler is None:
            activity.logger.warning("[%s] HiTL channel '%s' is not supported", tenant_id, channel)
            dispatch_results[channel] = "skipped:unsupported"
            continue

        try:
            await handler()
            dispatch_results[channel] = "ok"
        except Exception as exc:
            dispatch_results[channel] = f"error:{type(exc).__name__}"
            activity.logger.error(
                "[%s] HiTL channel '%s' dispatch failed error=%s",
                tenant_id,
                channel,
                type(exc).__name__,
            )

    return json.dumps(dispatch_results)
