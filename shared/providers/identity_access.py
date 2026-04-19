from __future__ import annotations

from typing import Any

from connectors.base import BaseConnector
from shared.models import IdentityUser


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
