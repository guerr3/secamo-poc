from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from azure.identity.aio import ClientSecretCredential

from connectors.base import BaseConnector
from shared.models import CanonicalEvent


class MicrosoftDefenderConnector(BaseConnector):
    """Microsoft Graph/Defender connector implementation."""

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

    async def fetch_events(self, query: dict) -> list[CanonicalEvent]:
        token = await self._get_graph_token()
        top = int(query.get("top", 20))
        url = f"https://graph.microsoft.com/v1.0/security/alerts_v2?$top={top}"

        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            payload = response.json()

        events: list[CanonicalEvent] = []
        for item in payload.get("value", []):
            events.append(
                CanonicalEvent(
                    event_type="defender.alert",
                    tenant_id=self.tenant_id,
                    provider=self.provider,
                    external_event_id=item.get("id"),
                    subject=item.get("title"),
                    severity=(item.get("severity") or "medium").lower(),
                    occurred_at=datetime.now(timezone.utc),
                    payload={
                        "alert_id": item.get("id", ""),
                        "severity": (item.get("severity") or "medium").lower(),
                        "title": item.get("title", ""),
                        "description": item.get("description", ""),
                        "device_id": (item.get("deviceEvidence") or [{}])[0].get("deviceId") if item.get("deviceEvidence") else None,
                        "user_email": (item.get("userStates") or [{}])[0].get("userPrincipalName") if item.get("userStates") else None,
                        "source_ip": item.get("ipAddress"),
                    },
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
