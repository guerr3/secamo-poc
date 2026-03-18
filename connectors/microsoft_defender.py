from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx
from azure.identity.aio import ClientSecretCredential

from connectors.base import BaseConnector
from shared.models import CanonicalEvent


class MicrosoftGraphConnector(BaseConnector):
    """Microsoft Graph/Defender connector implementation."""

    _RESOURCE_CONFIG: dict[str, dict[str, str]] = {
        "defender_alerts": {
            "path": "/security/alerts_v2",
            "event_type": "defender.alert",
            "occurred_field": "createdDateTime",
            "filter_field": "createdDateTime",
            "provider_event_type": "alert",
        },
        "entra_risky_users": {
            "path": "/identityProtection/riskyUsers",
            "event_type": "entra.risky_user",
            "occurred_field": "riskLastUpdatedDateTime",
            "filter_field": "riskLastUpdatedDateTime",
            "provider_event_type": "risky_user",
        },
        "entra_signin_logs": {
            "path": "/auditLogs/signIns",
            "event_type": "entra.signin_log",
            "occurred_field": "createdDateTime",
            "filter_field": "createdDateTime",
            "provider_event_type": "impossible_travel",
        },
        "intune_noncompliant_devices": {
            "path": "/deviceManagement/managedDevices",
            "event_type": "intune.noncompliant_device",
            "occurred_field": "lastSyncDateTime",
            "filter_field": "lastSyncDateTime",
            "base_filter": "complianceState eq 'noncompliant'",
            "provider_event_type": "noncompliant_device",
        },
        "entra_audit_logs": {
            "path": "/auditLogs/directoryAudits",
            "event_type": "entra.audit_log",
            "occurred_field": "activityDateTime",
            "filter_field": "activityDateTime",
            "provider_event_type": "audit_log",
        },
    }

    @property
    def provider(self) -> str:
        return "microsoft_defender"

    async def _get_graph_token(self) -> str:
        credential = ClientSecretCredential(
            tenant_id=self.secrets.tenant_azure_id,
            client_id=self.secrets.client_id,
            client_secret=self.secrets.client_secret,
        )
        try:
            token = await credential.get_token("https://graph.microsoft.com/.default")
            return token.token
        finally:
            await credential.close()

    @staticmethod
    def _parse_iso_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        parsed = value
        if parsed.endswith("Z"):
            parsed = parsed[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(parsed)
        except ValueError:
            return None

    @staticmethod
    def _format_odata_datetime(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def _map_event(self, item: dict[str, Any], resource_type: str, occurred_field: str, event_type: str, provider_event_type: str) -> CanonicalEvent:
        occurred_at = self._parse_iso_datetime(item.get(occurred_field))
        external_id = str(item.get("id") or item.get("alertId") or "")

        base_payload: dict[str, Any] = {
            "resource_type": resource_type,
            "provider_event_type": provider_event_type,
            **item,
        }

        if resource_type == "defender_alerts":
            payload = {
                "alert_id": item.get("id", ""),
                "severity": (item.get("severity") or "medium").lower(),
                "title": item.get("title", ""),
                "description": item.get("description", ""),
                "device_id": (item.get("deviceEvidence") or [{}])[0].get("deviceId") if item.get("deviceEvidence") else None,
                "user_email": (item.get("userStates") or [{}])[0].get("userPrincipalName") if item.get("userStates") else None,
                "source_ip": item.get("ipAddress"),
            }
            base_payload.update(payload)

        return CanonicalEvent(
            event_type=event_type,
            tenant_id=self.tenant_id,
            provider=self.provider,
            external_event_id=external_id or None,
            subject=item.get("title") or item.get("userPrincipalName") or external_id,
            severity=(item.get("severity") or "medium").lower() if item.get("severity") else None,
            occurred_at=occurred_at,
            payload=base_payload,
        )

    async def fetch_events(self, query: dict) -> list[CanonicalEvent]:
        token = await self._get_graph_token()
        top = int(query.get("top", 20))
        resource_type = str(query.get("resource_type", "defender_alerts")).strip().lower() or "defender_alerts"
        resource_config = self._RESOURCE_CONFIG.get(resource_type)
        if resource_config is None:
            raise ValueError(f"Unsupported resource_type '{resource_type}' for provider '{self.provider}'")

        since_raw = query.get("since")
        since_dt = self._parse_iso_datetime(str(since_raw)) if since_raw else None
        if since_dt is None:
            since_dt = datetime.now(timezone.utc) - timedelta(hours=24)

        filter_field = resource_config["filter_field"]
        since_filter = f"{filter_field} gt {self._format_odata_datetime(since_dt)}"

        base_filter = resource_config.get("base_filter")
        combined_filter = f"({base_filter}) and ({since_filter})" if base_filter else since_filter

        url = f"https://graph.microsoft.com/v1.0{resource_config['path']}"
        params = {
            "$top": str(top),
            "$filter": combined_filter,
            "$orderby": f"{filter_field} asc",
        }

        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            payload = response.json()

        events: list[CanonicalEvent] = []
        for item in payload.get("value", []):
            events.append(
                self._map_event(
                    item=item,
                    resource_type=resource_type,
                    occurred_field=resource_config["occurred_field"],
                    event_type=resource_config["event_type"],
                    provider_event_type=resource_config["provider_event_type"],
                )
            )
        return events

    async def execute_action(self, action: str, payload: dict) -> dict:
        token = await self._get_graph_token()
        headers = {"Authorization": f"Bearer {token}"}

        if action == "enrich_alert":
            alert_id = payload["alert_id"]
            url = f"https://graph.microsoft.com/v1.0/security/alerts_v2/{quote(alert_id)}"
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                return response.json()

        if action == "get_user_alerts":
            user_email = payload["user_email"]
            filt = quote(f"userStates/any(u:u/userPrincipalName eq '{user_email}')")
            url = f"https://graph.microsoft.com/v1.0/security/alerts_v2?$filter={filt}"
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                body = response.json()
                return {"alerts": body.get("value", [])}

        if action == "isolate_device":
            # TODO: validate tenant API permissions for Defender isolate endpoint.
            device_id = payload["device_id"]
            comment = payload.get("comment", "Isolated by Secamo workflow")
            body = {"Comment": comment, "IsolationType": "Full"}
            url = f"https://api.securitycenter.microsoft.com/api/machines/{quote(device_id)}/isolate"
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(url, headers=headers, json=body)
                response.raise_for_status()
                return response.json() if response.content else {"status": "submitted"}

        raise ValueError(f"Unsupported action '{action}' for provider '{self.provider}'")

    async def health_check(self) -> dict:
        token = await self._get_graph_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = "https://graph.microsoft.com/v1.0/organization?$top=1"
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            ok = response.status_code == 200
            return {
                "healthy": ok,
                "status_code": response.status_code,
                "provider": self.provider,
            }


# Backwards-compatible alias for older imports.
MicrosoftDefenderConnector = MicrosoftGraphConnector
