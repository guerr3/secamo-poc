from __future__ import annotations

import httpx
from temporalio import activity

from shared.models import NotificationResult


def _result(success: bool, channel: str, message_id: str | None = None) -> NotificationResult:
    return NotificationResult(success=success, channel=channel, message_id=message_id)


@activity.defn
async def teams_send_notification(tenant_id: str, channel_webhook_url: str, message: str) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] teams_send_notification")
    if not channel_webhook_url:
        activity.logger.error(f"[{tenant_id}] teams_send_notification missing webhook url")
        return _result(False, "teams")

    payload = {"@type": "MessageCard", "text": message}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                channel_webhook_url,
                headers={"Content-Type": "application/json"},
                json=payload,
            )
        if response.status_code >= 400:
            activity.logger.error(
                f"[{tenant_id}] teams_send_notification failed status={response.status_code}"
            )
            return _result(False, "teams")
        return _result(True, "teams", message_id=response.headers.get("x-ms-request-id"))
    except Exception as exc:
        activity.logger.error(
            f"[{tenant_id}] teams_send_notification error={type(exc).__name__}"
        )
        return _result(False, "teams")


@activity.defn
async def teams_send_adaptive_card(tenant_id: str, channel_webhook_url: str, card_payload: dict) -> NotificationResult:
    activity.logger.info(f"[{tenant_id}] teams_send_adaptive_card")
    if not channel_webhook_url:
        activity.logger.error(f"[{tenant_id}] teams_send_adaptive_card missing webhook url")
        return _result(False, "teams")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                channel_webhook_url,
                headers={"Content-Type": "application/json"},
                json=card_payload,
            )
        if response.status_code >= 400:
            activity.logger.error(
                f"[{tenant_id}] teams_send_adaptive_card failed status={response.status_code}"
            )
            return _result(False, "teams")
        return _result(True, "teams", message_id=response.headers.get("x-ms-request-id"))
    except Exception as exc:
        activity.logger.error(
            f"[{tenant_id}] teams_send_adaptive_card error={type(exc).__name__}"
        )
        return _result(False, "teams")
