from __future__ import annotations

from urllib.parse import quote

import httpx
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._activity_errors import application_error_from_http_status, raise_activity_error
from shared.graph_client import get_graph_token
from shared.models import AlertData, EnrichedAlert, TenantSecrets

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SECURITY_BASE = "https://graph.microsoft.com/v1.0/security"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@activity.defn
async def graph_enrich_alert(tenant_id: str, alert: AlertData, secrets: TenantSecrets) -> EnrichedAlert:
    activity.logger.info(f"[{tenant_id}] graph_enrich_alert: {alert.alert_id}")
    alert_id = alert.alert_id
    severity = (alert.severity or "medium").lower()
    title = alert.title
    description = alert.description
    user_display_name = None
    user_department = None
    device_display_name = None
    device_os = None
    device_compliance = None

    try:
        graph_token = await get_graph_token(secrets)
    except ApplicationError:
        raise
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] graph_enrich_alert token error: {type(exc).__name__}",
            error_type="GraphAlertTokenError",
            non_retryable=False,
        )

    async with httpx.AsyncClient(timeout=30.0) as client:
        alert_resp = await client.get(
            f"{SECURITY_BASE}/alerts_v2/{quote(alert.alert_id)}",
            headers=_auth_headers(graph_token),
        )
        if alert_resp.status_code >= 400 and alert_resp.status_code != 404:
            raise application_error_from_http_status(
                tenant_id,
                "microsoft_graph",
                "graph_enrich_alert_get_alert",
                alert_resp.status_code,
            )
        if alert_resp.status_code == 200:
            alert_body = alert_resp.json()
            alert_id = alert_body.get("id") or alert_id
            severity = (alert_body.get("severity") or severity).lower()
            title = alert_body.get("title") or title
            description = alert_body.get("description") or description

        if alert.user_email:
            user_resp = await client.get(
                f"{GRAPH_BASE}/users/{quote(alert.user_email)}?$select=displayName,department",
                headers=_auth_headers(graph_token),
            )
            if user_resp.status_code >= 400 and user_resp.status_code != 404:
                raise application_error_from_http_status(
                    tenant_id,
                    "microsoft_graph",
                    "graph_enrich_alert_get_user",
                    user_resp.status_code,
                )
            if user_resp.status_code == 200:
                user_body = user_resp.json()
                user_display_name = user_body.get("displayName")
                user_department = user_body.get("department")

        if alert.device_id:
            device_resp = await client.get(
                f"{GRAPH_BASE}/deviceManagement/managedDevices/{quote(alert.device_id)}?$select=deviceName,operatingSystem,complianceState",
                headers=_auth_headers(graph_token),
            )
            if device_resp.status_code >= 400 and device_resp.status_code != 404:
                raise application_error_from_http_status(
                    tenant_id,
                    "microsoft_graph",
                    "graph_enrich_alert_get_device",
                    device_resp.status_code,
                )
            if device_resp.status_code == 200:
                device_body = device_resp.json()
                device_display_name = device_body.get("deviceName")
                device_os = device_body.get("operatingSystem") or device_body.get("osPlatform")
                compliance_state = str(device_body.get("complianceState", "")).lower()
                if compliance_state in {"compliant", "noncompliant"}:
                    device_compliance = compliance_state
                elif "isCompliant" in device_body:
                    device_compliance = "compliant" if device_body.get("isCompliant") is True else "noncompliant"

    return EnrichedAlert(
        alert_id=alert_id,
        severity=severity,
        title=title,
        description=description,
        user_display_name=user_display_name,
        user_department=user_department,
        device_display_name=device_display_name,
        device_os=device_os,
        device_compliance=device_compliance,
    )


@activity.defn
async def graph_get_alerts(tenant_id: str, user_email: str, secrets: TenantSecrets) -> list[dict]:
    activity.logger.info(f"[{tenant_id}] graph_get_alerts: {user_email}")
    graph_token = await get_graph_token(secrets)
    filter_q = quote(f"userStates/any(u:u/userPrincipalName eq '{user_email}')")
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{SECURITY_BASE}/alerts_v2?$filter={filter_q}&$top=10",
            headers=_auth_headers(graph_token),
        )

    if response.status_code != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_get_alerts",
            response.status_code,
        )

    return response.json().get("value", [])[:10]
