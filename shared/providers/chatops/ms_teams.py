"""Microsoft Teams ChatOps provider using Adaptive Card message payloads."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import httpx

from shared.models import ChatOpsMessage


class MSTeamsChatOpsProvider:
    """Send and validate ChatOps interactions for Microsoft Teams.

    This provider supports outbound messages via Teams incoming webhooks and
    optional HMAC validation for inbound action callbacks when a shared signing
    secret is configured.
    """

    def __init__(
        self,
        *,
        webhook_url: str,
        signing_secret: str | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        """Initialize a Teams provider instance.

        Args:
            webhook_url: Teams webhook target URL.
            signing_secret: Optional secret for inbound signature validation.
            timeout_seconds: HTTP timeout in seconds.
        """

        self._webhook_url = webhook_url
        self._signing_secret = signing_secret
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
        """Normalize header dictionary keys for case-insensitive access."""
        return {str(k).lower(): str(v) for k, v in headers.items()}

    @staticmethod
    def _adaptive_action(action_id: str, title: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Build one Adaptive Card submit action from normalized ChatOps action data."""
        return {
            "type": "Action.Submit",
            "title": title,
            "data": {
                "action_id": action_id,
                **payload,
            },
        }

    @classmethod
    def _build_adaptive_card_payload(cls, message: ChatOpsMessage) -> dict[str, Any]:
        """Convert a provider-agnostic message into Teams Adaptive Card format."""
        actions = [
            cls._adaptive_action(action.action_id, action.label, action.payload)
            for action in message.actions
        ]

        card: dict[str, Any] = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": message.title,
                    "weight": "Bolder",
                    "size": "Medium",
                    "wrap": True,
                },
                {
                    "type": "TextBlock",
                    "text": message.body,
                    "wrap": True,
                },
            ],
        }

        if actions:
            card["actions"] = actions

        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        }

    async def send_message(self, target_channel: str, message: ChatOpsMessage) -> str:
        """Send an Adaptive Card message and return a provider reference id."""
        # Teams incoming webhooks encode destination in the webhook itself.
        # target_channel is retained to satisfy protocol parity across providers.
        _ = target_channel

        payload = self._build_adaptive_card_payload(message)
        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            response = await client.post(
                self._webhook_url,
                headers={"Content-Type": "application/json"},
                json=payload,
            )

        if response.status_code >= 400:
            raise RuntimeError(f"Teams send_message failed with status={response.status_code}")

        return response.headers.get("x-ms-request-id") or response.headers.get("request-id") or "teams-message-sent"

    async def validate_webhook_signature(self, headers: dict[str, str], body: bytes) -> bool:
        """Validate webhook body integrity when a shared HMAC secret is configured.

        Expected header (case-insensitive):
            - ``x-ms-signature`` or ``x-secamo-signature`` containing a SHA256 hex digest.
        """
        if not self._signing_secret:
            return False

        normalized = self._normalize_headers(headers)
        received = normalized.get("x-ms-signature") or normalized.get("x-secamo-signature")
        if not received:
            return False

        computed = hmac.new(
            self._signing_secret.encode("utf-8"),
            body,
            digestmod=hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(received, computed)

    @staticmethod
    def parse_action_payload(body: bytes) -> dict[str, Any]:
        """Parse Teams callback payload body into a dictionary."""
        decoded = body.decode("utf-8")
        parsed = json.loads(decoded)
        if not isinstance(parsed, dict):
            raise ValueError("Teams action payload must be a JSON object")
        return parsed
