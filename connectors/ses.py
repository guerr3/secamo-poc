from __future__ import annotations

import os
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from connectors.base import BaseConnector
from connectors.errors import (
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)
from shared.models import Envelope
from shared.providers.contracts import TenantSecrets


_TRANSIENT_ERROR_CODES = {
    "RequestTimeout",
    "ServiceUnavailable",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
}

_PERMANENT_ERROR_CODES = {
    "AccountSendingPausedException",
    "ConfigurationSetDoesNotExistException",
    "InvalidParameterValue",
    "MailFromDomainNotVerifiedException",
    "MessageRejected",
    "ValidationError",
}


class SesConnector(BaseConnector):
    """AWS SES connector for outbound email delivery."""

    def __init__(self, tenant_id: str, secrets: TenantSecrets) -> None:
        super().__init__(tenant_id, secrets)
        region = os.environ.get("AWS_REGION", "eu-west-1").strip() or "eu-west-1"
        self._ses = boto3.client("ses", region_name=region)
        self._region = region

    @property
    def provider(self) -> str:
        return "ses"

    async def fetch_events(self, query: dict) -> list[Envelope]:
        return []

    def _translate_client_error(self, action: str, error: ClientError) -> None:
        code = str(error.response.get("Error", {}).get("Code") or "Unknown")
        message = str(error.response.get("Error", {}).get("Message") or str(error))

        if code in _TRANSIENT_ERROR_CODES:
            raise ConnectorTransientError(f"SES {action} failed transiently ({code}): {message}") from error

        if code in _PERMANENT_ERROR_CODES:
            raise ConnectorPermanentError(f"SES {action} failed permanently ({code}): {message}") from error

        raise ConnectorPermanentError(f"SES {action} failed ({code}): {message}") from error

    @staticmethod
    def _normalize_recipients(to_value: Any) -> list[str]:
        if isinstance(to_value, str):
            recipients = [to_value.strip()]
        elif isinstance(to_value, list):
            recipients = [str(item).strip() for item in to_value if str(item).strip()]
        else:
            recipients = []

        return [recipient for recipient in recipients if recipient]

    async def execute_action(self, action: str, payload: dict) -> dict:
        if action != "send_email":
            raise ConnectorUnsupportedActionError(f"SES connector does not support action '{action}'")

        sender = str(payload.get("sender") or "").strip()
        recipients = self._normalize_recipients(payload.get("to"))
        subject = str(payload.get("subject") or "").strip()
        body = str(payload.get("body") or "")
        content_type = str(payload.get("content_type") or "Text").strip().lower()

        if not sender:
            raise ConnectorPermanentError("SES send_email requires non-empty 'sender'")
        if not recipients:
            raise ConnectorPermanentError("SES send_email requires at least one recipient in 'to'")
        if not subject:
            raise ConnectorPermanentError("SES send_email requires non-empty 'subject'")
        if not body:
            raise ConnectorPermanentError("SES send_email requires non-empty 'body'")

        body_key = "Html" if content_type == "html" else "Text"

        try:
            response = self._ses.send_email(
                Source=sender,
                Destination={"ToAddresses": recipients},
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {
                        body_key: {
                            "Data": body,
                            "Charset": "UTF-8",
                        }
                    },
                },
            )
        except ClientError as error:
            self._translate_client_error("send_email", error)
        except BotoCoreError as error:
            raise ConnectorTransientError(f"SES send_email failed transiently: {error}") from error

        message_id = str(response.get("MessageId") or "").strip()
        return {
            "success": True,
            "sent": True,
            "message_id": message_id or None,
            "provider": self.provider,
            "region": self._region,
            "details": "Email accepted by SES",
        }

    async def health_check(self) -> dict:
        try:
            quota = self._ses.get_send_quota()
        except ClientError as error:
            self._translate_client_error("health_check", error)
        except BotoCoreError as error:
            raise ConnectorTransientError(f"SES health_check failed transiently: {error}") from error

        return {
            "healthy": True,
            "provider": self.provider,
            "region": self._region,
            "max_24_hour_send": float(quota.get("Max24HourSend", 0.0)),
            "max_send_rate": float(quota.get("MaxSendRate", 0.0)),
            "sent_last_24_hours": float(quota.get("SentLast24Hours", 0.0)),
        }
