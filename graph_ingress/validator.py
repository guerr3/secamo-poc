from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import boto3
import jwt

from shared.models import GraphNotificationEnvelope, GraphNotificationItem

GRAPH_SUBSCRIPTIONS_TABLE = os.environ.get("GRAPH_SUBSCRIPTIONS_TABLE", "").strip()
GRAPH_NOTIFICATION_APP_IDS = {
    value.strip() for value in os.environ.get("GRAPH_NOTIFICATION_APP_IDS", "").split(",") if value.strip()
}
GRAPH_NOTIFICATION_AZP = "0bf30f3b-4a52-48df-9a82-234910c4a086"
GRAPH_COMMON_JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"


@dataclass(frozen=True)
class ResolvedNotification:
    tenant_id: str
    item: GraphNotificationItem


class GraphIngressValidator:
    """Validate Graph webhook notifications and resolve tenant context."""

    def __init__(self, *, validation_app_ids: set[str] | None = None) -> None:
        self._ddb = None
        self._validation_app_ids = set(validation_app_ids or GRAPH_NOTIFICATION_APP_IDS)
        self._jwks_client = jwt.PyJWKClient(GRAPH_COMMON_JWKS_URL)

    def _get_dynamodb(self):
        if self._ddb is None:
            self._ddb = boto3.resource("dynamodb", region_name="eu-west-1")
        return self._ddb

    def _get_subscription_metadata(self, subscription_id: str) -> dict[str, Any] | None:
        if not GRAPH_SUBSCRIPTIONS_TABLE:
            return None

        table = self._get_dynamodb().Table(GRAPH_SUBSCRIPTIONS_TABLE)
        response = table.get_item(Key={"subscription_id": subscription_id})
        metadata = response.get("Item")
        if not isinstance(metadata, dict):
            return None
        return metadata

    def _validate_validation_tokens(self, tokens: list[str] | None) -> bool:
        if not tokens:
            return True

        if not self._validation_app_ids:
            return False

        for token in tokens:
            try:
                signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
                claims = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=list(self._validation_app_ids),
                    options={"require": ["exp", "iat", "iss", "aud", "azp"]},
                )
            except Exception:
                return False

            issuer = str(claims.get("iss") or "")
            if not issuer.startswith("https://login.microsoftonline.com/"):
                return False
            if str(claims.get("azp") or "") != GRAPH_NOTIFICATION_AZP:
                return False

        return True

    def resolve_tenant_id(self, item: GraphNotificationItem) -> str | None:
        metadata = self._get_subscription_metadata(item.subscriptionId)
        if not metadata:
            return None

        client_state = str(item.clientState or "")
        expected_client_state = str(metadata.get("client_state") or "")
        if not expected_client_state or expected_client_state != client_state:
            return None

        return str(metadata.get("tenant_id") or "") or None

    def validate_and_resolve(
        self,
        envelope: GraphNotificationEnvelope,
    ) -> list[ResolvedNotification]:
        if not self._validate_validation_tokens(envelope.validationTokens):
            return []

        resolved: list[ResolvedNotification] = []
        for item in envelope.value:
            tenant_id = self.resolve_tenant_id(item)
            if not tenant_id:
                continue
            resolved.append(ResolvedNotification(tenant_id=tenant_id, item=item))
        return resolved
