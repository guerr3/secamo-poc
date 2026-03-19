"""Slack ChatOps provider using Block Kit message payloads."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

import httpx

from shared.models import ChatOpsMessage


class SlackChatOpsProvider:
    """Send and validate ChatOps interactions for Slack.

    Supports either Incoming Webhooks or the Web API ``chat.postMessage`` using
    a bot token. Webhook signature validation follows Slack's documented signing
    process based on ``X-Slack-Signature`` and ``X-Slack-Request-Timestamp``.
    """

    def __init__(
        self,
        *,
        webhook_url: str | None = None,
        bot_token: str | None = None,
        signing_secret: str | None = None,
        api_base_url: str = "https://slack.com/api",
        timeout_seconds: float = 30.0,
    ) -> None:
        """Initialize a Slack provider instance.

        Args:
            webhook_url: Optional Slack incoming webhook URL.
            bot_token: Optional OAuth token for chat.postMessage.
            signing_secret: Slack app signing secret for callback verification.
            api_base_url: Slack API base URL.
            timeout_seconds: HTTP timeout in seconds.
        """

        self._webhook_url = webhook_url
        self._bot_token = bot_token
        self._signing_secret = signing_secret
        self._api_base_url = api_base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
        """Normalize header keys for case-insensitive lookups."""
        return {str(k).lower(): str(v) for k, v in headers.items()}

    @staticmethod
    def _build_block_kit_payload(target_channel: str, message: ChatOpsMessage) -> dict[str, Any]:
        """Transform generic ChatOps message into Slack Block Kit payload."""
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": message.title[:150],
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message.body,
                },
            },
        ]

        if message.actions:
            action_elements = []
            for action in message.actions:
                action_elements.append(
                    {
                        "type": "button",
                        "action_id": action.action_id,
                        "text": {
                            "type": "plain_text",
                            "text": action.label[:75],
                            "emoji": True,
                        },
                        "value": json.dumps(action.payload, ensure_ascii=True),
                    }
                )
            blocks.append({"type": "actions", "elements": action_elements})

        return {
            "channel": target_channel,
            "text": f"{message.title}: {message.body}",
            "blocks": blocks,
        }

    async def send_message(self, target_channel: str, message: ChatOpsMessage) -> str:
        """Send a Block Kit message and return the Slack message identifier."""
        payload = self._build_block_kit_payload(target_channel, message)

        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            if self._webhook_url:
                webhook_payload = {
                    "text": payload["text"],
                    "blocks": payload["blocks"],
                }
                response = await client.post(self._webhook_url, json=webhook_payload)
                if response.status_code >= 400:
                    raise RuntimeError(f"Slack webhook send failed with status={response.status_code}")
                return "slack-webhook-message-sent"

            if not self._bot_token:
                raise RuntimeError("Slack provider requires either webhook_url or bot_token")

            response = await client.post(
                f"{self._api_base_url}/chat.postMessage",
                headers={
                    "Authorization": f"Bearer {self._bot_token}",
                    "Content-Type": "application/json; charset=utf-8",
                },
                json=payload,
            )
            if response.status_code >= 400:
                raise RuntimeError(f"Slack chat.postMessage failed with status={response.status_code}")

            body = response.json()
            if not body.get("ok", False):
                raise RuntimeError(f"Slack chat.postMessage failed: {body.get('error', 'unknown_error')}")

            channel = str(body.get("channel", ""))
            timestamp = str(body.get("ts", ""))
            return f"{channel}:{timestamp}" if channel and timestamp else "slack-message-sent"

    async def validate_webhook_signature(self, headers: dict[str, str], body: bytes) -> bool:
        """Validate Slack request signature and timestamp (anti-replay)."""
        if not self._signing_secret:
            return False

        normalized = self._normalize_headers(headers)
        timestamp = normalized.get("x-slack-request-timestamp")
        signature = normalized.get("x-slack-signature")
        if not timestamp or not signature:
            return False

        try:
            request_ts = int(timestamp)
        except ValueError:
            return False

        if abs(int(time.time()) - request_ts) > 300:
            return False

        base_string = f"v0:{timestamp}:{body.decode('utf-8')}"
        digest = hmac.new(
            self._signing_secret.encode("utf-8"),
            base_string.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        computed = f"v0={digest}"
        return hmac.compare_digest(computed, signature)

    @staticmethod
    def parse_action_payload(body: bytes) -> dict[str, Any]:
        """Parse Slack interactive action body into a JSON dictionary."""
        decoded = body.decode("utf-8")
        try:
            parsed = json.loads(decoded)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        # Slack commonly sends URL-encoded form body: payload=<json>
        for item in decoded.split("&"):
            if item.startswith("payload="):
                payload_json = item[len("payload=") :]
                payload_json = payload_json.replace("+", " ")
                payload_json = httpx.QueryParams(f"payload={payload_json}").get("payload") or "{}"
                loaded = json.loads(payload_json)
                if isinstance(loaded, dict):
                    return loaded

        raise ValueError("Unable to parse Slack action payload")
