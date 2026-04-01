"""EDR provider protocol and connector-backed implementation.

No Temporal imports. Factory resolves secret_type internally.
"""

from __future__ import annotations

from typing import Any

from connectors.registry import get_connector
from shared.models import DeviceContext, IdentityRiskContext
from shared.providers.contracts import TenantSecrets
from shared.providers.protocols import ConnectorInterface, EDRProvider


class ConnectorEDRProvider:
    """EDR provider backed by connector actions."""

    def __init__(self, *, connector: ConnectorInterface) -> None:
        self._connector = connector

    async def enrich_alert(self, alert_id: str, context: dict[str, Any] | None = None) -> dict:
        payload: dict[str, Any] = {"alert_id": alert_id}
        if context:
            payload.update(context)
        return await self._connector.execute_action("enrich_alert_context", payload)

    async def get_device_context(self, device_id: str) -> DeviceContext | None:
        result = await self._connector.execute_action("get_device_context", {"device_id": device_id})
        if isinstance(result, dict) and result.get("found") is False:
            return None
        return DeviceContext(
            provider=self._connector.provider,
            device_id=str(result.get("device_id") or device_id),
            display_name=result.get("display_name"),
            os_platform=result.get("os_platform"),
            compliance_state=result.get("compliance_state"),
            risk_score=result.get("risk_score"),
        )

    async def isolate_device(self, device_id: str, comment: str) -> bool:
        result = await self._connector.execute_action(
            "isolate_device", {"device_id": device_id, "comment": comment}
        )
        if isinstance(result, dict) and result.get("found") is False:
            return False
        return bool(result.get("submitted", True)) if isinstance(result, dict) else True

    async def unisolate_device(self, device_id: str, comment: str) -> bool:
        result = await self._connector.execute_action(
            "unisolate_device", {"device_id": device_id, "comment": comment}
        )
        if isinstance(result, dict) and result.get("found") is False:
            return False
        return bool(result.get("submitted", True)) if isinstance(result, dict) else True

    async def run_antivirus_scan(self, device_id: str, scan_type: str) -> dict:
        normalized_scan = "Full" if str(scan_type).lower() == "full" else "Quick"
        result = await self._connector.execute_action(
            "run_antivirus_scan", {"device_id": device_id, "scan_type": normalized_scan}
        )
        return result if isinstance(result, dict) else {}

    async def list_noncompliant_devices(self) -> list[dict]:
        result = await self._connector.execute_action("list_noncompliant_devices", {})
        return list(result.get("devices", [])) if isinstance(result, dict) else []

    async def get_user_alerts(self, user_email: str, top: int = 10) -> list[dict]:
        result = await self._connector.execute_action(
            "list_user_alerts", {"user_email": user_email}
        )
        return list(result.get("alerts", []))[:top] if isinstance(result, dict) else []

    async def confirm_user_compromised(self, user_id: str) -> bool:
        result = await self._connector.execute_action(
            "confirm_user_compromised", {"user_id": user_id}
        )
        return bool(result.get("confirmed", False)) if isinstance(result, dict) else False

    async def dismiss_risky_user(self, user_id: str) -> bool:
        result = await self._connector.execute_action(
            "dismiss_risky_user", {"user_id": user_id}
        )
        return bool(result.get("dismissed", False)) if isinstance(result, dict) else False

    async def get_signin_history(self, user_principal_name: str, top: int = 20) -> list[dict]:
        result = await self._connector.execute_action(
            "get_signin_history", {"user_principal_name": user_principal_name, "top": top}
        )
        return list(result.get("signins", [])) if isinstance(result, dict) else []

    async def list_risky_users(self, min_risk_level: str) -> list[dict]:
        result = await self._connector.execute_action(
            "list_risky_users", {"min_risk_level": min_risk_level}
        )
        return list(result.get("users", [])) if isinstance(result, dict) else []

    async def get_identity_risk(self, lookup_key: str) -> IdentityRiskContext | None:
        result = await self._connector.execute_action(
            "list_risky_users", {"lookup_key": lookup_key, "min_risk_level": "low"}
        )
        users = result.get("users", []) if isinstance(result, dict) else []
        if not users:
            return None
        user = users[0]
        return IdentityRiskContext(
            provider=self._connector.provider,
            subject=(
                user.get("userPrincipalName")
                or user.get("user_principal_name")
                or user.get("userDisplayName")
                or user.get("user_display_name")
                or str(user.get("id", ""))
            ),
            risk_level=user.get("riskLevel") or user.get("risk_level"),
            risk_state=user.get("riskState") or user.get("risk_state"),
            risk_detail=user.get("riskDetail") or user.get("risk_detail"),
        )


def get_edr_provider(
    tenant_id: str,
    secrets: TenantSecrets,
    *,
    provider: str = "microsoft_defender",
) -> EDRProvider:
    """Resolve an EDR provider for the given tenant.

    Args:
        tenant_id: Tenant identifier.
        secrets: Pre-loaded tenant secrets.
        provider: EDR provider name (from TenantConfig.edr_provider).

    Returns:
        A protocol-compatible EDR provider instance.
    """
    connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
    return ConnectorEDRProvider(connector=connector)
