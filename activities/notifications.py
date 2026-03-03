from temporalio import activity
from shared.models import NotificationResult


@activity.defn
async def teams_send_notification(
    tenant_id: str,
    channel_webhook_url: str,
    message: str,
) -> NotificationResult:
    """
    Stuurt een tekstbericht naar een Microsoft Teams-kanaal via webhook.
    Later: POST naar Teams Incoming Webhook URL.
    """
    activity.logger.info(
        f"[{tenant_id}] Teams notificatie versturen naar webhook"
    )

    # TODO: replace with real Teams webhook POST
    return NotificationResult(
        success=True,
        channel="teams",
        message_id="msg-stub-001",
    )


@activity.defn
async def teams_send_adaptive_card(
    tenant_id: str,
    channel_webhook_url: str,
    card_payload: dict,
) -> NotificationResult:
    """
    Stuurt een Adaptive Card naar Microsoft Teams (voor HITL-goedkeuringen).
    Later: POST Adaptive Card JSON naar Teams webhook.
    """
    activity.logger.info(
        f"[{tenant_id}] Teams Adaptive Card versturen voor goedkeuring"
    )

    # TODO: replace with real Teams Adaptive Card POST
    return NotificationResult(
        success=True,
        channel="teams",
        message_id="card-stub-001",
    )


@activity.defn
async def email_send(
    tenant_id: str,
    to: str,
    subject: str,
    body: str,
) -> NotificationResult:
    """
    Verstuurt een e-mail via Microsoft Graph API (Send Mail).
    Later: POST /me/sendMail of /users/{id}/sendMail via msgraph-sdk.
    """
    activity.logger.info(
        f"[{tenant_id}] E-mail versturen naar '{to}' — onderwerp: {subject}"
    )

    # TODO: replace with real Graph Send Mail API call
    return NotificationResult(
        success=True,
        channel="email",
        message_id="email-stub-001",
    )
