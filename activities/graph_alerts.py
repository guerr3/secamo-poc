from __future__ import annotations

from urllib.parse import quote

import httpx
from temporalio import activity

from shared.graph_client import get_defender_token, get_graph_token
from shared.models import AlertData, EnrichedAlert, RiskScore, TenantSecrets, ThreatIntelResult
from shared.ssm_client import get_secret

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SECURITY_BASE = "https://graph.microsoft.com/v1.0/security"
DEFENDER_BASE = "https://api.securitycenter.microsoft.com/api"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _handle_http_error(tenant_id: str, provider: str, status: int, action: str) -> None:
    if status in (401, 403):
        raise RuntimeError(f"[{tenant_id}] Auth failed for {provider}: {status}")
    if status == 429:
        raise RuntimeError(f"[{tenant_id}] {provider} rate limited during {action}: {status}")
    if status >= 500:
        raise RuntimeError(f"[{tenant_id}] {provider} server error during {action}: {status}")


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
    except Exception as exc:
        activity.logger.error(f"[{tenant_id}] graph_enrich_alert token error: {type(exc).__name__}")
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

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            alert_resp = await client.get(
                f"{SECURITY_BASE}/alerts_v2/{quote(alert.alert_id)}",
                headers=_auth_headers(graph_token),
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
                if user_resp.status_code == 200:
                    user_body = user_resp.json()
                    user_display_name = user_body.get("displayName")
                    user_department = user_body.get("department")

            if alert.device_id:
                device_resp = await client.get(
                    f"{GRAPH_BASE}/deviceManagement/managedDevices/{quote(alert.device_id)}?$select=deviceName,operatingSystem,complianceState",
                    headers=_auth_headers(graph_token),
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
    except Exception as exc:
        activity.logger.error(f"[{tenant_id}] graph_enrich_alert non-fatal error: {type(exc).__name__}")

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
    try:
        graph_token = await get_graph_token(secrets)
        filter_q = quote(f"userStates/any(u:u/userPrincipalName eq '{user_email}')")
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{SECURITY_BASE}/alerts_v2?$filter={filter_q}&$top=10",
                headers=_auth_headers(graph_token),
            )

        if response.status_code != 200:
            return []

        return response.json().get("value", [])[:10]
    except Exception as exc:
        activity.logger.error(f"[{tenant_id}] graph_get_alerts non-fatal error: {type(exc).__name__}")
        return []


@activity.defn
async def graph_isolate_device(tenant_id: str, device_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_isolate_device: {device_id}")
    token = await get_defender_token(secrets)
    payload = {"Comment": "Isolated by Secamo orchestrator", "IsolationType": "Full"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{DEFENDER_BASE}/machines/{quote(device_id)}/isolate",
            headers=_auth_headers(token),
            json=payload,
        )

    if response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_defender", response.status_code, "graph_isolate_device")
    return response.status_code == 201


@activity.defn
async def threat_intel_lookup(tenant_id: str, indicator: str) -> ThreatIntelResult:
    activity.logger.info(f"[{tenant_id}] threat_intel_lookup")
    if not indicator:
        return ThreatIntelResult(
            indicator="",
            is_malicious=False,
            provider="none",
            reputation_score=0.0,
            details="empty indicator",
        )

    api_key = get_secret(tenant_id, "threatintel/virustotal_api_key") or get_secret(tenant_id, "threatintel/api_key")
    if not api_key:
        return ThreatIntelResult(
            indicator=indicator,
            is_malicious=False,
            provider="none",
            reputation_score=0.0,
            details="no threat intel configured",
        )

    headers = {"x-apikey": api_key}
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{quote(indicator)}",
            headers=headers,
        )

    if response.status_code == 404:
        return ThreatIntelResult(
            indicator=indicator,
            is_malicious=False,
            provider="virustotal",
            reputation_score=0.0,
            details="indicator not found",
        )

    _handle_http_error(tenant_id, "virustotal", response.status_code, "threat_intel_lookup")
    if response.status_code != 200:
        raise RuntimeError(f"[{tenant_id}] threat_intel_lookup failed: {response.status_code}")

    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious_votes = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total_votes = max(
        malicious_votes
        + int(stats.get("harmless", 0))
        + int(stats.get("undetected", 0))
        + int(stats.get("timeout", 0)),
        1,
    )
    score = min((malicious_votes / total_votes) * 100.0, 100.0)

    return ThreatIntelResult(
        indicator=indicator,
        is_malicious=score > 20.0,
        provider="virustotal",
        reputation_score=round(score, 2),
        details="VirusTotal reputation lookup",
    )


@activity.defn
async def calculate_risk_score(tenant_id: str, enriched_alert: EnrichedAlert, threat_intel: ThreatIntelResult) -> RiskScore:
    activity.logger.info(f"[{tenant_id}] calculate_risk_score: {enriched_alert.alert_id}")
    base = {
        "low": 20.0,
        "medium": 40.0,
        "high": 70.0,
        "critical": 90.0,
    }.get((enriched_alert.severity or "medium").lower(), 40.0)

    factors: list[str] = []
    if threat_intel.is_malicious:
        base += 15.0
        factors.append("Threat intel marked indicator as malicious")
    if (enriched_alert.device_compliance or "").lower() == "noncompliant":
        base += 10.0
        factors.append("Device is noncompliant")
    if (enriched_alert.user_department or "").lower() in {"finance", "executive", "hr"}:
        base += 5.0
        factors.append("Privileged/high-risk user department")

    score = min(base, 100.0)
    if score < 40:
        level = "low"
    elif score < 70:
        level = "medium"
    elif score < 90:
        level = "high"
    else:
        level = "critical"

    return RiskScore(
        alert_id=enriched_alert.alert_id,
        score=score,
        level=level,
        factors=factors,
    )
