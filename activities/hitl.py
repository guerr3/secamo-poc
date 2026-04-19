from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import time
from urllib.parse import urlencode

import boto3
from botocore.exceptions import ClientError
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._activity_errors import raise_activity_error
from activities.provider_capabilities import connector_execute_action
from activities.tenant import get_tenant_config
from shared.config import EMAIL_PROVIDER, SECAMO_SENDER_EMAIL
from shared.models import (
    ChatOpsAction,
    ChatOpsMessage,
    HitlCallbackBinding,
    HitlChannelDispatchResult,
    HitlDispatchResult,
    HiTLRequest,
)
from shared.providers.factory import get_chatops_provider
from shared.ssm_client import get_secret_bundle


_EMAIL_ACTION_CAPABLE_PROVIDERS = {"microsoft_defender", "microsoft_graph", "ses"}


def _render_metadata_rows(metadata: dict) -> str:
    return "".join(
        f"<tr><td style='padding:6px 8px;border:1px solid #e5e7eb;'><b>{key}</b></td>"
        f"<td style='padding:6px 8px;border:1px solid #e5e7eb;'>{value}</td></tr>"
        for key, value in metadata.items()
    )


def _render_action_buttons(action_urls: dict[str, str]) -> str:
    return "".join(
        f"<a href='{url}' style='display:inline-block;margin:8px 8px 0 0;padding:10px 16px;"
        f"background:#0b5ed7;color:#ffffff;text-decoration:none;border-radius:6px;'>"
        f"{action.replace('_', ' ').title()}</a>"
        for action, url in action_urls.items()
    )


def _render_metadata_section(metadata_rows: str) -> str:
    if not metadata_rows:
        return ""
    return (
        "<h3 style='margin:16px 0 8px 0;font-family:Segoe UI,Arial,sans-serif;'>Context</h3>"
        "<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:14px;'>"
        f"{metadata_rows}</table>"
    )


def _render_approval_email(request: HiTLRequest, action_urls: dict[str, str]) -> str:
    metadata_rows = _render_metadata_rows(request.metadata)
    action_buttons = _render_action_buttons(action_urls)
    metadata_section = _render_metadata_section(metadata_rows)

    return (
        "<html><body style='font-family:Segoe UI,Arial,sans-serif;color:#111827;'>"
        f"<h2 style='margin:0 0 12px 0;'>{request.title}</h2>"
        f"<p style='line-height:1.5;'>{request.description}</p>"
        f"{metadata_section}"
        "<h3 style='margin:18px 0 8px 0;'>Choose an action</h3>"
        f"<div>{action_buttons}</div>"
        "<p style='margin-top:14px;font-size:12px;color:#6b7280;'>"
        f"This link expires in {request.timeout_hours} hour(s) and can only be used once."
        "</p>"
        "</body></html>"
    )


def _render_jira_approval_description(request: HiTLRequest, action_urls: dict[str, str]) -> str:
    metadata_lines = "\n".join(
        f"- **{key}**: {value}"
        for key, value in request.metadata.items()
    )
    action_lines = "\n".join(
        f"- {action.replace('_', ' ').title()}: {url}"
        for action, url in action_urls.items()
    )

    metadata_section = ""
    if metadata_lines:
        metadata_section = f"\n\nContext:\n{metadata_lines}"

    return (
        f"{request.description}\n\n"
        "Approval links:\n"
        f"{action_lines}"
        f"{metadata_section}\n\n"
        "Alternative: set status to Approved/Resolved and add a comment with the intended action."
    )


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
        raise ApplicationError(
            "HITL_TOKEN_TABLE environment variable is not configured",
            type="MissingHitlTableConfig",
            non_retryable=True,
        )
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
            "channel": {"S": "hitl"},
            "expires_at": {"N": str(expires_at)},
        },
        # Use an expression attribute name because DynamoDB expression parsing
        # rejects reserved words in-place.
        ConditionExpression="attribute_not_exists(#token)",
        ExpressionAttributeNames={"#token": "token"},
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


def _secret_type_from_credentials_path(path_template: str) -> str:
    """Extract SSM secret_type from a configured credentials path template."""
    normalized = path_template.replace("{tenant_id}", "tenant-placeholder").strip("/")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return "chatops"
    return parts[-1]


async def _load_secret_bundle_async(tenant_id: str, secret_type: str) -> dict[str, str]:
    """Load tenant secret bundle via thread offloading for boto3-backed calls."""
    return await asyncio.to_thread(get_secret_bundle, tenant_id, secret_type)


def _dispatch_ok(channel: str, message_id: str | None = None) -> HitlChannelDispatchResult:
    return HitlChannelDispatchResult(channel=channel, success=True, message_id=message_id)


def _dispatch_error(channel: str, error_type: str, error_message: str) -> HitlChannelDispatchResult:
    return HitlChannelDispatchResult(
        channel=channel,
        success=False,
        error_type=error_type,
        error_message=error_message,
    )


def _build_callback_binding(request: HiTLRequest) -> HitlCallbackBinding:
    token = _deterministic_token(request)
    try:
        _put_token_record(request, token)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "ConditionalCheckFailedException":
            raise

    parameter_name = f"/{_name_prefix()}/hitl/endpoint_base_url"
    endpoint = _ssm.get_parameter(Name=parameter_name, WithDecryption=False)
    callback_endpoint = endpoint.get("Parameter", {}).get("Value", "").strip()
    if not callback_endpoint:
        raise_activity_error(
            f"Empty HiTL endpoint base URL in SSM parameter: {parameter_name}",
            error_type="MissingHitlEndpointConfig",
            non_retryable=True,
        )

    return HitlCallbackBinding(
        token=token,
        callback_endpoint=callback_endpoint,
        workflow_id=request.workflow_id,
        run_id=request.run_id,
        allowed_actions=tuple(request.allowed_actions),
    )


def _resolve_email_connector_provider() -> str:
    provider = EMAIL_PROVIDER.strip().lower() or "ses"
    if provider in _EMAIL_ACTION_CAPABLE_PROVIDERS:
        return provider

    raise_activity_error(
        f"Unsupported EMAIL_PROVIDER value '{provider}'",
        error_type="EmailProviderConfigurationError",
        non_retryable=True,
    )


async def _dispatch_email(
    request: HiTLRequest,
    binding: HitlCallbackBinding,
) -> HitlChannelDispatchResult:
    action_urls = {
        action: _join_query_url(binding.callback_endpoint, binding.token, action)
        for action in binding.allowed_actions
    }

    email_html = _render_approval_email(request, action_urls)
    if not SECAMO_SENDER_EMAIL:
        raise_activity_error(
            f"[{request.tenant_id}] SECAMO_SENDER_EMAIL is not configured",
            error_type="MissingSenderEmail",
            non_retryable=True,
        )

    email_provider = _resolve_email_connector_provider()

    action_result = await connector_execute_action(
        request.tenant_id,
        email_provider,
        "send_email",
        {
            "sender": SECAMO_SENDER_EMAIL,
            "to": request.reviewer_email,
            "subject": f"[Secamo Approval] {request.title}",
            "body": email_html,
            "content_type": "HTML",
        },
    )
    result_payload = action_result.data.payload

    activity.logger.info(
        "[%s] HiTL email dispatched token=%s... recipient=%s",
        request.tenant_id,
        binding.token[:8],
        request.reviewer_email,
    )
    return _dispatch_ok("email", message_id=str(result_payload.get("message_id") or "") or None)


async def _dispatch_teams(
    request: HiTLRequest,
    binding: HitlCallbackBinding,
) -> HitlChannelDispatchResult:
    cfg = await get_tenant_config(request.tenant_id)
    if not cfg.chatops_config.enabled:
        return _dispatch_error("teams", "ChatOpsDisabled", "ChatOps is disabled for tenant")

    secret_type = _secret_type_from_credentials_path(cfg.chatops_config.credentials_path)
    secrets = await _load_secret_bundle_async(request.tenant_id, secret_type)
    if not secrets:
        return _dispatch_error("teams", "MissingTenantSecrets", "No ChatOps secrets found")

    provider = await get_chatops_provider(request.tenant_id, secrets, cfg)

    resolved_channel = cfg.chatops_config.default_channel
    if not resolved_channel and cfg.chatops_config.default_channels:
        resolved_channel = cfg.chatops_config.default_channels[0]
    if not resolved_channel:
        return _dispatch_error("teams", "MissingChatOpsChannel", "No ChatOps target channel configured")

    actions = [
        ChatOpsAction(
            action_id=action,
            label=action.replace("_", " ").title(),
            payload={
                "token": binding.token,
                "action": action,
                "workflow_id": binding.workflow_id,
                "run_id": binding.run_id,
            },
        )
        for action in binding.allowed_actions
    ]

    message = ChatOpsMessage(
        title=request.title,
        body=request.description,
        actions=actions,
        metadata={
            "workflow_id": binding.workflow_id,
            "run_id": binding.run_id,
            "ticket_key": request.ticket_key or "",
        },
    )

    message_id = await provider.send_message(target_channel=resolved_channel, message=message)
    return _dispatch_ok("teams", message_id=message_id)


async def _dispatch_ticketing(
    request: HiTLRequest,
    binding: HitlCallbackBinding,
    *,
    channel_name: str,
) -> HitlChannelDispatchResult:
    action_urls = {
        action: _join_query_url(binding.callback_endpoint, binding.token, action)
        for action in binding.allowed_actions
    }

    labels = [
        f"secamo-wf:{binding.workflow_id}",
        f"secamo-run:{binding.run_id}",
        "secamo-hitl",
    ]

    if request.ticket_key:
        labels.append(f"secamo-parent:{request.ticket_key}")

    cfg = await get_tenant_config(request.tenant_id)
    ticketing_provider = cfg.ticketing_provider

    description = _render_jira_approval_description(request, action_urls)
    action_result = await connector_execute_action(
        request.tenant_id,
        ticketing_provider,
        "create_ticket",
        {
            "title": request.title,
            "description": description,
            "labels": labels,
            "request_field_values": {
                "summary": request.title,
                "description": description,
            },
            "priority": request.metadata.get("severity"),
        },
    )

    payload = action_result.data.payload
    ticket_ref = str(payload.get("key") or payload.get("issueKey") or payload.get("id") or "").strip()

    activity.logger.info(
        "[%s] HiTL ticket dispatched workflow_id=%s provider=%s ticket_ref=%s",
        request.tenant_id,
        binding.workflow_id,
        ticketing_provider,
        ticket_ref or "unknown",
    )
    return _dispatch_ok(channel_name, message_id=ticket_ref or None)


async def _dispatch_jira(
    request: HiTLRequest,
    binding: HitlCallbackBinding,
) -> HitlChannelDispatchResult:
    return await _dispatch_ticketing(request, binding, channel_name="jira")


@activity.defn
async def request_hitl_approval(
    tenant_id: str,
    request: HiTLRequest,
) -> HitlDispatchResult:
    activity.logger.info(
        "[%s] request_hitl_approval workflow_id=%s channels=%s",
        tenant_id,
        request.workflow_id,
        request.channels,
    )

    binding = _build_callback_binding(request)
    channel_results: list[HitlChannelDispatchResult] = []

    async def _dispatch_channel(channel: str) -> HitlChannelDispatchResult:
        normalized = channel.strip().lower()
        if normalized == "email":
            return await _dispatch_email(request, binding)
        if normalized == "teams":
            return await _dispatch_teams(request, binding)
        if normalized == "jira":
            return await _dispatch_jira(request, binding)
        if normalized == "ticketing":
            return await _dispatch_ticketing(request, binding, channel_name="ticketing")
        return _dispatch_error(channel, "UnsupportedChannel", f"HiTL channel '{channel}' is not supported")

    for channel in request.channels:
        heartbeat_payload = {
            "channel": channel,
            "results": [result.model_dump(mode="json") for result in channel_results],
        }
        activity.heartbeat(heartbeat_payload)

        try:
            result = await _dispatch_channel(channel)
            channel_results.append(result)
            if not result.success:
                activity.logger.warning(
                    "[%s] HiTL channel '%s' dispatch failed error=%s",
                    tenant_id,
                    channel,
                    result.error_type,
                )
        except ApplicationError as exc:
            channel_results.append(
                _dispatch_error(channel, exc.type or "ApplicationError", str(exc)),
            )
        except Exception as exc:
            channel_results.append(_dispatch_error(channel, type(exc).__name__, str(exc)))

    successful_channels = [result.channel for result in channel_results if result.success]
    failed_channels = [result.channel for result in channel_results if not result.success]
    if not successful_channels:
        raise_activity_error(
            f"[{tenant_id}] HiTL dispatch failed for channels={','.join(failed_channels)}",
            error_type="HiTLDispatchFailed",
            non_retryable=False,
        )

    return HitlDispatchResult(
        workflow_id=binding.workflow_id,
        run_id=binding.run_id,
        token_preview=f"{binding.token[:8]}...",
        channel_results=channel_results,
        any_channel_succeeded=bool(successful_channels),
        failed_channels=failed_channels,
    )
