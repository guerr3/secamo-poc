from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from connectors.base import BaseConnector
from connectors.errors import (
    ConnectorPermanentError,
    ConnectorTransientError,
    ConnectorUnsupportedActionError,
)
from shared.graph_client import get_defender_token, get_graph_token
from shared.models import CanonicalEvent


class MicrosoftGraphConnector(BaseConnector):
    """Microsoft Graph/Defender connector implementation."""

    _MAX_ATTEMPTS = 3

    _RESOURCE_CONFIG: dict[str, dict[str, Any]] = {
        "defender_alerts": {
            "path": "/security/alerts_v2",
            "event_type": "defender.alert",
            "occurred_field": "createdDateTime",
            "filter_field": "createdDateTime",
            "provider_event_type": "alert",
            "supports_orderby": False,
        },
        "entra_risky_users": {
            "path": "/identityProtection/riskyUsers",
            "event_type": "entra.risky_user",
            "occurred_field": "riskLastUpdatedDateTime",
            "filter_field": "riskLastUpdatedDateTime",
            "provider_event_type": "risky_user",
            "supports_orderby": False,
            "max_top": 500,
        },
        "entra_signin_logs": {
            "path": "/auditLogs/signIns",
            "event_type": "entra.signin_log",
            "occurred_field": "createdDateTime",
            "filter_field": "createdDateTime",
            "provider_event_type": "impossible_travel",
            "supports_orderby": False,
        },
        "intune_noncompliant_devices": {
            "path": "/deviceManagement/managedDevices",
            "event_type": "intune.noncompliant_device",
            "occurred_field": "lastSyncDateTime",
            "filter_field": "lastSyncDateTime",
            "base_filter": "complianceState eq 'noncompliant'",
            "provider_event_type": "noncompliant_device",
            "supports_orderby": False,
        },
        "entra_audit_logs": {
            "path": "/auditLogs/directoryAudits",
            "event_type": "entra.audit_log",
            "occurred_field": "activityDateTime",
            "filter_field": "activityDateTime",
            "provider_event_type": "audit_log",
            "supports_orderby": False,
        },
    }

    @property
    def provider(self) -> str:
        return "microsoft_defender"

    @staticmethod
    def _retry_delay_seconds(retry_after_header: str | None, attempt: int) -> float:
        if retry_after_header:
            try:
                return max(0.0, float(retry_after_header))
            except ValueError:
                pass
        return float(min(2 ** (attempt - 1), 30))

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        timeout: float = 20.0,
    ) -> httpx.Response:
        last_error: Exception | None = None

        for attempt in range(1, self._MAX_ATTEMPTS + 1):
            try:
                # Open a new connection on each attempt to avoid sticky failures.
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        json=json,
                    )
            except httpx.RequestError as exc:
                last_error = exc
                if attempt == self._MAX_ATTEMPTS:
                    break
                await asyncio.sleep(self._retry_delay_seconds(None, attempt))
                continue

            if response.status_code in (429, 503):
                if attempt == self._MAX_ATTEMPTS:
                    raise ConnectorTransientError(
                        f"Graph request throttled/unavailable after retries: status={response.status_code} url={url}"
                    )
                await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                continue

            if response.status_code in (400, 401, 403, 404):
                raise ConnectorPermanentError(
                    f"Graph request rejected: status={response.status_code} url={url}"
                )

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if 500 <= response.status_code < 600:
                    last_error = exc
                    if attempt == self._MAX_ATTEMPTS:
                        break
                    await asyncio.sleep(self._retry_delay_seconds(response.headers.get("Retry-After"), attempt))
                    continue
                raise ConnectorPermanentError(
                    f"Graph request failed: status={response.status_code} url={url}"
                ) from exc

            return response

        raise ConnectorTransientError(f"Graph request failed after retries: {url}") from last_error

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

    @staticmethod
    def _escape_odata_literal(value: str) -> str:
        return value.replace("'", "''")

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
        token = await get_graph_token(self.secrets)
        top = int(query.get("top", 20))
        resource_type = str(query.get("resource_type", "defender_alerts")).strip().lower() or "defender_alerts"
        resource_config = self._RESOURCE_CONFIG.get(resource_type)
        if resource_config is None:
            raise ConnectorUnsupportedActionError(
                f"Unsupported resource_type '{resource_type}' for provider '{self.provider}'"
            )
        max_top = resource_config.get("max_top")
        if isinstance(max_top, int):
            top = min(top, max_top)

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
        }
        if bool(resource_config.get("supports_orderby")):
            params["$orderby"] = f"{filter_field} asc"

        headers = {"Authorization": f"Bearer {token}"}
        events: list[CanonicalEvent] = []
        next_url: str | None = url
        next_params: dict[str, str] | None = params
        visited_urls: set[str] = set()
        while next_url:
            if next_url in visited_urls:
                break
            visited_urls.add(next_url)

            response = await self._request_with_retry(
                "GET",
                next_url,
                headers=headers,
                params=next_params,
            )
            payload = response.json()

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
            next_url = payload.get("@odata.nextLink")
            next_params = None
        return events

    async def execute_action(self, action: str, payload: dict) -> dict:
        if action == "enrich_alert":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            alert_id = payload["alert_id"]
            url = f"https://graph.microsoft.com/v1.0/security/alerts_v2/{quote(alert_id)}"
            response = await self._request_with_retry("GET", url, headers=headers)
            return response.json()

        if action == "get_user_alerts":
            token = await get_graph_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            user_email = payload["user_email"]
            escaped_email = self._escape_odata_literal(user_email)
            filt = f"userStates/any(u:u/userPrincipalName eq '{escaped_email}')"
            url = "https://graph.microsoft.com/v1.0/security/alerts_v2"
            response = await self._request_with_retry("GET", url, headers=headers, params={"$filter": filt})
            body = response.json()
            return {"alerts": body.get("value", [])}

        if action == "isolate_device":
            # TODO: validate tenant API permissions for Defender isolate endpoint.
            token = await get_defender_token(self.secrets)
            headers = {"Authorization": f"Bearer {token}"}
            device_id = payload["device_id"]
            comment = payload.get("comment", "Isolated by Secamo workflow")
            body = {"Comment": comment, "IsolationType": "Full"}
            url = f"https://api.securitycenter.microsoft.com/api/machines/{quote(device_id)}/isolate"
            response = await self._request_with_retry("POST", url, headers=headers, json=body)
            return response.json() if response.content else {"status": "submitted"}

        raise ConnectorUnsupportedActionError(
            f"Unsupported action '{action}' for provider '{self.provider}'"
        )

    async def health_check(self) -> dict:
        token = await get_graph_token(self.secrets)
        headers = {"Authorization": f"Bearer {token}"}
        url = "https://graph.microsoft.com/v1.0/organization?$top=1"
        response = await self._request_with_retry("GET", url, headers=headers, timeout=15.0)
        ok = response.status_code == 200
        return {
            "healthy": ok,
            "status_code": response.status_code,
            "provider": self.provider,
        }


# Backwards-compatible alias for older imports.
MicrosoftDefenderConnector = MicrosoftGraphConnector
