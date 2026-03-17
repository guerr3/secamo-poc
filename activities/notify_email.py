from __future__ import annotations

import httpx
from temporalio import activity

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


def _result(success: bool, channel: str, message_id: str | None = None) -> NotificationResult:
    return NotificationResult(success=success, channel=channel, message_id=message_id)


@activity.defn
async def email_send(tenant_id: str, to: str, subject: str, body: str) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] email_send to={to}")

    try:
        secrets = _load_graph_secrets(tenant_id)
        token = await get_graph_token(secrets)
        sender = SECAMO_SENDER_EMAIL

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
                f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )

        if response.status_code >= 400:
            activity.logger.error(f"[{tenant_id}] email_send failed status={response.status_code}")
            return _result(False, "email")
        return _result(True, "email", message_id=response.headers.get("x-ms-request-id"))
    except Exception as exc:
        activity.logger.error(f"[{tenant_id}] email_send error={type(exc).__name__}")
        return _result(False, "email")
