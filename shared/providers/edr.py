"""EDR provider protocol and connector-backed implementation.

No Temporal imports. Factory resolves secret_type internally.
"""

from __future__ import annotations

from typing import Any

from shared.models.canonical import Envelope
from shared.models import (
    AlertEnrichmentResult,
    AlertSummary,
    ConnectorActionData,
    ConnectorActionResult,
    DeviceContext,
    SignInEvent,
)
from shared.providers.protocols import ConnectorInterface


class ConnectorEDRProvider:
    """EDR provider backed by connector actions."""

    def __init__(self, *, connector: ConnectorInterface) -> None:
        self._connector = connector

    def _action_result(self, *, action: str, payload: dict[str, Any], default_details: str) -> ConnectorActionResult:
        submitted = bool(payload.get("submitted", True))
        found = payload.get("found") is not False
        success = bool(payload.get("success", True)) and submitted and found
        details = str(payload.get("details") or default_details)
        return ConnectorActionResult(
            provider=self._connector.provider,
            operation_type="action",
            success=success,
            details=details,
            data=ConnectorActionData(action=action, payload=payload),
        )

    async def fetch_events(self, query: dict[str, Any]) -> list[Envelope]:
        return await self._connector.fetch_events(query)

    async def enrich_alert(self, alert_id: str, context: dict[str, Any] | None = None) -> AlertEnrichmentResult:
        payload: dict[str, Any] = {"alert_id": alert_id}
        if context:
            payload.update(context)
        result = await self._connector.execute_action("enrich_alert_context", payload)
        return AlertEnrichmentResult.model_validate(result if isinstance(result, dict) else {})

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

    async def isolate_device(self, device_id: str, comment: str) -> ConnectorActionResult:
        result = await self._connector.execute_action(
            "isolate_device", {"device_id": device_id, "comment": comment}
        )
        payload = result if isinstance(result, dict) else {}
        return self._action_result(action="isolate_device", payload=payload, default_details="device isolation submitted")

    async def unisolate_device(self, device_id: str, comment: str) -> ConnectorActionResult:
        result = await self._connector.execute_action(
            "unisolate_device", {"device_id": device_id, "comment": comment}
        )
        payload = result if isinstance(result, dict) else {}
        return self._action_result(action="unisolate_device", payload=payload, default_details="device unisolation submitted")

    async def run_antivirus_scan(self, device_id: str, scan_type: str) -> ConnectorActionResult:
        normalized_scan = "Full" if str(scan_type).lower() == "full" else "Quick"
        result = await self._connector.execute_action(
            "run_antivirus_scan", {"device_id": device_id, "scan_type": normalized_scan}
        )
        payload = result if isinstance(result, dict) else {}
        return self._action_result(action="run_antivirus_scan", payload=payload, default_details="scan action submitted")

    async def list_noncompliant_devices(self) -> list[DeviceContext]:
        result = await self._connector.execute_action("list_noncompliant_devices", {})
        devices = list(result.get("devices", [])) if isinstance(result, dict) else []
        typed_devices: list[DeviceContext] = []
        for device in devices:
            if not isinstance(device, dict):
                continue
            typed_devices.append(
                DeviceContext(
                    provider=self._connector.provider,
                    device_id=str(device.get("id") or device.get("deviceId") or ""),
                    display_name=device.get("deviceName") or device.get("display_name"),
                    os_platform=device.get("operatingSystem") or device.get("os_platform"),
                    compliance_state=device.get("complianceState") or device.get("compliance_state"),
                    risk_score=device.get("riskScore") or device.get("risk_score"),
                )
            )
        return typed_devices

    async def get_user_alerts(self, user_email: str, top: int = 10) -> list[AlertSummary]:
        result = await self._connector.execute_action(
            "list_user_alerts", {"user_email": user_email}
        )
        alerts = list(result.get("alerts", []))[:top] if isinstance(result, dict) else []
        typed_alerts: list[AlertSummary] = []
        for alert in alerts:
            if isinstance(alert, dict):
                typed_alerts.append(AlertSummary.model_validate(alert))
        return typed_alerts

    async def get_signin_history(self, user_principal_name: str, top: int = 20) -> list[SignInEvent]:
        result = await self._connector.execute_action(
            "get_signin_history", {"user_principal_name": user_principal_name, "top": top}
        )
        signins = list(result.get("signins", [])) if isinstance(result, dict) else []
        typed_signins: list[SignInEvent] = []
        for signin in signins:
            if isinstance(signin, dict):
                typed_signins.append(SignInEvent.model_validate(signin))
        return typed_signins
