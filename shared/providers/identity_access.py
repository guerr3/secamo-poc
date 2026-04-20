from __future__ import annotations

from typing import Any

from connectors.base import BaseConnector
from shared.models import IdentityRiskContext, IdentityUser


class ConnectorIdentityAccessProvider:
    """Identity access provider backed by connector actions."""

    def __init__(self, *, identity_provider: str, connector: BaseConnector) -> None:
        self._identity_provider = identity_provider
        self._connector = connector

    @staticmethod
    def _to_identity_user(payload: dict[str, Any], fallback_email: str | None = None, provider: str = "unknown") -> IdentityUser:
        email = str(
            payload.get("email")
            or payload.get("mail")
            or payload.get("userPrincipalName")
            or fallback_email
            or ""
        )
        return IdentityUser(
            identity_provider=provider,
            user_id=str(payload.get("user_id") or payload.get("id") or ""),
            email=email,
            display_name=str(payload.get("display_name") or payload.get("displayName") or ""),
            account_enabled=bool(payload.get("account_enabled", payload.get("accountEnabled", True))),
        )

    @staticmethod
    def _to_identity_risk_context(payload: dict[str, Any], provider: str) -> IdentityRiskContext:
        return IdentityRiskContext(
            provider=provider,
            subject=(
                payload.get("subject")
                or payload.get("userPrincipalName")
                or payload.get("user_principal_name")
                or payload.get("userDisplayName")
                or payload.get("user_display_name")
                or str(payload.get("id", ""))
            ),
            risk_level=payload.get("risk_level") or payload.get("riskLevel"),
            risk_state=payload.get("risk_state") or payload.get("riskState"),
            risk_detail=payload.get("risk_detail") or payload.get("riskDetail"),
        )

    async def get_user(self, email: str) -> IdentityUser | None:
        result = await self._connector.execute_action("get_user", {"email": email})
        if isinstance(result, dict) and result.get("found") is False:
            return None
        if not isinstance(result, dict):
            return None
        return self._to_identity_user(result, fallback_email=email, provider=self._identity_provider)

    async def create_user(self, user_data: dict[str, Any]) -> IdentityUser:
        result = await self._connector.execute_action("create_user", {"user_data": user_data})
        return self._to_identity_user(result if isinstance(result, dict) else {}, fallback_email=str(user_data.get("email") or ""), provider=self._identity_provider)

    async def update_user(self, user_id: str, updates: dict[str, Any]) -> bool:
        result = await self._connector.execute_action("update_user", {"user_id": user_id, "updates": updates})
        if isinstance(result, dict):
            return bool(result.get("updated", result.get("success", True)))
        return True

    async def delete_user(self, user_id: str) -> bool:
        result = await self._connector.execute_action("delete_user", {"user_id": user_id})
        if isinstance(result, dict):
            return bool(result.get("deleted", result.get("success", True)))
        return True

    async def revoke_sessions(self, user_id: str) -> bool:
        result = await self._connector.execute_action("revoke_sessions", {"user_id": user_id})
        if isinstance(result, dict):
            return bool(result.get("revoked", result.get("success", True)))
        return True

    async def assign_license(self, user_id: str, sku_id: str) -> bool:
        result = await self._connector.execute_action("assign_license", {"user_id": user_id, "sku_id": sku_id})
        if isinstance(result, dict):
            return bool(result.get("assigned", result.get("success", True)))
        return True

    async def reset_password(self, user_id: str, temp_password: str) -> bool:
        result = await self._connector.execute_action(
            "reset_password",
            {"user_id": user_id, "temp_password": temp_password},
        )
        if isinstance(result, dict):
            return bool(result.get("reset", result.get("success", True)))
        return True

    async def list_risky_users(self, min_risk_level: str) -> list[IdentityRiskContext]:
        result = await self._connector.execute_action(
            "list_risky_users", {"min_risk_level": min_risk_level}
        )
        users = list(result.get("users", [])) if isinstance(result, dict) else []
        typed_users: list[IdentityRiskContext] = []
        for user in users:
            if isinstance(user, dict):
                typed_users.append(self._to_identity_risk_context(user, provider=self._identity_provider))
        return typed_users

    async def get_identity_risk(self, lookup_key: str) -> IdentityRiskContext | None:
        result = await self._connector.execute_action(
            "get_identity_risk", {"lookup_key": lookup_key}
        )
        if not isinstance(result, dict) or result.get("found") is False:
            return None
        return self._to_identity_risk_context(result, provider=self._identity_provider)

    async def confirm_user_compromised(self, user_id: str) -> bool:
        result = await self._connector.execute_action(
            "confirm_user_compromised", {"user_id": user_id}
        )
        if isinstance(result, dict):
            return bool(result.get("confirmed", result.get("success", False)))
        return False

    async def dismiss_risky_user(self, user_id: str) -> bool:
        result = await self._connector.execute_action(
            "dismiss_risky_user", {"user_id": user_id}
        )
        if isinstance(result, dict):
            return bool(result.get("dismissed", result.get("success", False)))
        return False
