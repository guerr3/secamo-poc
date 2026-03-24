from __future__ import annotations

import asyncio
from urllib.parse import quote

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._activity_errors import application_error_from_http_status, raise_activity_error
from shared.config import SECAMO_SENDER_EMAIL
from shared.graph_client import get_graph_token
from shared.models import NotificationResult, TenantSecrets
from shared.ssm_client import get_secret_bundle


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
        secrets = await _load_graph_secrets_async(tenant_id)
        token = await get_graph_token(secrets)
        sender = SECAMO_SENDER_EMAIL
        if not sender:
            raise_activity_error(
                f"[{tenant_id}] SECAMO_SENDER_EMAIL is not configured",
                error_type="MissingSenderEmail",
                non_retryable=True,
            )

        payload = {
            "message": {
                "subject": subject,
                "body": {"contentType": "Text", "content": body},
                "toRecipients": [{"emailAddress": {"address": to}}],
            },
            "saveToSentItems": "false",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"https://graph.microsoft.com/v1.0/users/{quote(sender)}/sendMail",
                headers={
                    "Authorization": f"Bearer {token}",
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
                tenant_id,
                "microsoft_graph",
                "email_send",
                response.status_code,
                retry_after_seconds=retry_after_seconds,
            )
        return _result(True, "email", message_id=response.headers.get("x-ms-request-id"))
    except ApplicationError:
        raise
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] email_send unexpected error={type(exc).__name__}",
            error_type="EmailSendUnexpectedError",
            non_retryable=False,
        )
