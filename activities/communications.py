from __future__ import annotations

import asyncio
import json

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._activity_errors import raise_activity_error
from activities.provider_capabilities import connector_execute_action
from activities.tenant import get_tenant_config
from shared.config import EMAIL_PROVIDER, SECAMO_SENDER_EMAIL
from shared.models import ChatOpsMessage, NotificationResult
from shared.providers.factory import get_chatops_provider
from shared.providers.types import secret_type_for_provider
from shared.ssm_client import get_secret_bundle


_EMAIL_ACTION_CAPABLE_PROVIDERS = {"microsoft_defender", "microsoft_graph", "ses"}


async def _load_secret_bundle_async(tenant_id: str, secret_type: str) -> dict[str, str]:
    return await asyncio.to_thread(get_secret_bundle, tenant_id, secret_type)


def _secret_type_from_credentials_path(path_template: str) -> str:
    normalized = path_template.replace("{tenant_id}", "tenant-placeholder").strip("/")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return "chatops"
    return parts[-1]


def _effective_chatops_provider_type(notification_provider: str, fallback_provider_type: str) -> str:
    normalized = (notification_provider or "").strip().lower()
    if normalized == "slack":
        return "slack"
    if normalized in {"teams", "email"}:
        return "ms_teams"
    return fallback_provider_type


async def _resolve_chatops_target(tenant_id: str, target_channel: str):
    config = await get_tenant_config(tenant_id)
    if not config.chatops_config.enabled:
        raise_activity_error(
            f"[{tenant_id}] ChatOps is disabled for tenant",
            error_type="ChatOpsDisabled",
            non_retryable=True,
        )

    provider_type = _effective_chatops_provider_type(
        config.notification_provider,
        config.chatops_config.provider_type,
    )
    if provider_type != config.chatops_config.provider_type:
        config = config.model_copy(
            update={
                "chatops_config": config.chatops_config.model_copy(
                    update={"provider_type": provider_type}
                )
            }
        )

    secret_type = _secret_type_from_credentials_path(config.chatops_config.credentials_path)
    secrets = await _load_secret_bundle_async(tenant_id, secret_type)
    provider = await get_chatops_provider(tenant_id, secrets, config)

    resolved_channel = target_channel.strip()
    if not resolved_channel:
        resolved_channel = config.chatops_config.default_channel or ""
    if not resolved_channel and config.chatops_config.default_channels:
        resolved_channel = config.chatops_config.default_channels[0]

    if config.chatops_config.provider_type == "slack" and not resolved_channel:
        raise_activity_error(
            f"[{tenant_id}] missing ChatOps target channel for Slack",
            error_type="MissingChatOpsChannel",
            non_retryable=True,
        )

    return provider, resolved_channel


def _result(success: bool, channel: str, message_id: str | None = None) -> NotificationResult:
    return NotificationResult(success=success, channel=channel, message_id=message_id)


def _resolve_email_connector_provider() -> str:
    provider = EMAIL_PROVIDER.strip().lower() or "ses"
    if provider in _EMAIL_ACTION_CAPABLE_PROVIDERS:
        return provider

    raise ValueError(
        "EMAIL_PROVIDER must be one of "
        f"{sorted(_EMAIL_ACTION_CAPABLE_PROVIDERS)}; got '{provider}'"
    )


@activity.defn
async def email_send(tenant_id: str, to: str, subject: str, body: str) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] email_send to={to}")
    try:
        provider_name = _resolve_email_connector_provider()
        secret_type = secret_type_for_provider(provider_name)
        await _load_secret_bundle_async(tenant_id, secret_type)

        sender = SECAMO_SENDER_EMAIL
        if not sender:
            raise_activity_error(
                f"[{tenant_id}] SECAMO_SENDER_EMAIL is not configured",
                error_type="MissingSenderEmail",
                non_retryable=True,
            )

        result = await connector_execute_action(
            tenant_id,
            provider_name,
            "send_email",
            {
                "sender": sender,
                "to": to,
                "subject": subject,
                "body": body,
                "content_type": "Text",
            },
        )
        payload = result.data.payload
        return _result(True, "email", message_id=str(payload.get("message_id") or "") or None)
    except ValueError as exc:
        raise_activity_error(
            f"[{tenant_id}] email_send configuration error: {exc}",
            error_type="EmailProviderConfigurationError",
            non_retryable=True,
        )
    except ApplicationError:
        raise
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] email_send unexpected error={type(exc).__name__}",
            error_type="EmailSendUnexpectedError",
            non_retryable=False,
        )


@activity.defn
async def teams_send_notification(tenant_id: str, channel_webhook_url: str, message: str) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] teams_send_notification")
    try:
        provider, resolved_channel = await _resolve_chatops_target(tenant_id, channel_webhook_url)
        message_id = await provider.send_message(
            target_channel=resolved_channel,
            message=ChatOpsMessage(
                title="Secamo Notification",
                body=message,
            ),
        )
        return _result(True, "teams", message_id=message_id)
    except ApplicationError:
        raise
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] teams_send_notification unexpected error={type(exc).__name__}",
            error_type="TeamsNotificationUnexpectedError",
            non_retryable=False,
        )


@activity.defn
async def teams_send_adaptive_card(tenant_id: str, channel_webhook_url: str, card_payload: dict) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] teams_send_adaptive_card")
    try:
        provider, resolved_channel = await _resolve_chatops_target(tenant_id, channel_webhook_url)

        title = str(card_payload.get("title") or card_payload.get("summary") or "Secamo Card")
        fallback_body = json.dumps(card_payload, ensure_ascii=True)
        body = str(card_payload.get("text") or card_payload.get("body") or fallback_body)

        message_id = await provider.send_message(
            target_channel=resolved_channel,
            message=ChatOpsMessage(
                title=title,
                body=body,
                metadata={"card_payload": card_payload},
            ),
        )
        return _result(True, "teams", message_id=message_id)
    except ApplicationError:
        raise
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] teams_send_adaptive_card unexpected error={type(exc).__name__}",
            error_type="TeamsAdaptiveCardUnexpectedError",
            non_retryable=False,
        )
