from __future__ import annotations

import asyncio
import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._activity_errors import application_error_from_http_status, raise_activity_error
from activities._tenant_secrets import load_tenant_secrets
from activities.connector_dispatch import connector_execute_action
from shared.config import SECAMO_SENDER_EMAIL
from shared.models import NotificationResult
from shared.providers.contracts import TenantSecrets
from shared.ssm_client import get_secret_bundle

# --- Email notification ---

def _load_graph_secrets(tenant_id: str) -> TenantSecrets:
    raw = get_secret_bundle(tenant_id, "graph")
    return TenantSecrets(
        client_id=raw.get("client_id", ""),
        client_secret=raw.get("client_secret", ""),
        tenant_azure_id=raw.get("tenant_azure_id", ""),
    )

async def _load_graph_secrets_async(tenant_id: str) -> TenantSecrets:
    return await asyncio.to_thread(_load_graph_secrets, tenant_id)

def _result(success: bool, channel: str, message_id: str | None = None) -> NotificationResult:
    return NotificationResult(success=success, channel=channel, message_id=message_id)

@activity.defn
async def email_send(tenant_id: str, to: str, subject: str, body: str) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] email_send to={to}")
    try:
        await _load_graph_secrets_async(tenant_id)
        sender = SECAMO_SENDER_EMAIL
        if not sender:
            raise_activity_error(
                f"[{tenant_id}] SECAMO_SENDER_EMAIL is not configured",
                error_type="MissingSenderEmail",
                non_retryable=True,
            )
        result = await connector_execute_action(
            tenant_id,
            "microsoft_defender",
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
    except ApplicationError:
        raise
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] email_send unexpected error={type(exc).__name__}",
            error_type="EmailSendUnexpectedError",
            non_retryable=False,
        )

# --- Teams notification ---

@activity.defn
async def teams_send_notification(tenant_id: str, channel_webhook_url: str, message: str) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] teams_send_notification")
    resolved_webhook_url = channel_webhook_url.strip()
    if not resolved_webhook_url:
        secrets = load_tenant_secrets(tenant_id, "graph")
        resolved_webhook_url = str(secrets.teams_webhook_url or "").strip()
    if not resolved_webhook_url:
        raise_activity_error(
            f"[{tenant_id}] teams_send_notification missing webhook url",
            error_type="MissingTeamsWebhook",
            non_retryable=True,
        )
    payload = {"@type": "MessageCard", "text": message}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                resolved_webhook_url,
                headers={"Content-Type": "application/json"},
                json=payload,
            )
        if response.status_code >= 400:
            raise application_error_from_http_status(
                tenant_id,
                "microsoft_teams",
                "teams_send_notification",
                response.status_code,
            )
        return _result(True, "teams", message_id=response.headers.get("x-ms-request-id"))
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
    if not channel_webhook_url:
        raise_activity_error(
            f"[{tenant_id}] teams_send_adaptive_card missing webhook url",
            error_type="MissingTeamsWebhook",
            non_retryable=True,
        )
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                channel_webhook_url,
                headers={"Content-Type": "application/json"},
                json=card_payload,
            )
        if response.status_code >= 400:
            raise application_error_from_http_status(
                tenant_id,
                "microsoft_teams",
                "teams_send_adaptive_card",
                response.status_code,
            )
        return _result(True, "teams", message_id=response.headers.get("x-ms-request-id"))
    except ApplicationError:
        raise
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] teams_send_adaptive_card unexpected error={type(exc).__name__}",
            error_type="TeamsAdaptiveCardUnexpectedError",
            non_retryable=False,
        )
