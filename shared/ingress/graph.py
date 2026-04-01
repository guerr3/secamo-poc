from __future__ import annotations

from typing import Any
from uuid import uuid4

import jwt


class GraphNotificationHelper:
    """Graph notification parsing and validation helpers shared by ingress adapters."""

    def __init__(
        self,
        *,
        graph_jwks_client: Any,
        notification_app_ids: set[str],
        notification_azp: str,
    ) -> None:
        self._graph_jwks_client = graph_jwks_client
        self._notification_app_ids = notification_app_ids
        self._notification_azp = notification_azp

    def validate_graph_validation_tokens(self, tokens: list[str] | None) -> bool:
        if not tokens:
            return True

        if not self._notification_app_ids:
            return False

        for token in tokens:
            try:
                signing_key = self._graph_jwks_client.get_signing_key_from_jwt(token).key
                claims = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=list(self._notification_app_ids),
                    options={"require": ["exp", "iat", "iss", "aud", "azp"]},
                )
            except Exception:
                return False

            issuer = str(claims.get("iss") or "")
            if not issuer.startswith("https://login.microsoftonline.com/"):
                return False
            if str(claims.get("azp") or "") != self._notification_azp:
                return False

        return True

    @staticmethod
    def graph_event_type_from_resource(resource: str) -> str:
        value = str(resource or "").strip().lower()
        if "alerts" in value:
            return "defender.alert"
        if "signin" in value or "risky" in value:
            return "defender.impossible_travel"
        return ""

    @staticmethod
    def graph_client_state_matches_tenant(client_state: str | None, tenant_id: str) -> bool:
        if not client_state:
            return True
        expected_prefix = f"secamo:{tenant_id}:"
        return str(client_state).startswith(expected_prefix)

    @staticmethod
    def graph_item_to_provider_payload(item: dict[str, Any], event_type: str) -> dict[str, Any]:
        resource_data = item.get("resourceData") if isinstance(item.get("resourceData"), dict) else {}
        alert_id = str(resource_data.get("id") or item.get("subscriptionId") or str(uuid4()))

        return {
            "event_type": event_type,
            "alert": {
                "id": alert_id,
                "severity": str(resource_data.get("severity") or "medium").lower(),
                "title": str(resource_data.get("title") or resource_data.get("riskEventType") or "Graph notification"),
                "description": str(resource_data.get("description") or resource_data.get("riskDetail") or ""),
                "deviceId": resource_data.get("deviceId") or resource_data.get("azureAdDeviceId"),
                "userPrincipalName": resource_data.get("userPrincipalName") or resource_data.get("accountName"),
                "ipAddress": resource_data.get("ipAddress"),
                "destinationIp": resource_data.get("destinationIp"),
            },
            "resource": item.get("resource"),
            "change_type": item.get("changeType"),
            "subscription_id": item.get("subscriptionId"),
            "client_state": item.get("clientState"),
        }
