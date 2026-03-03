from temporalio import activity
from shared.models import (
    AlertData,
    EnrichedAlert,
    ThreatIntelResult,
    RiskScore,
    TenantSecrets,
    GraphUser,
)
from typing import Optional


@activity.defn
async def graph_enrich_alert(
    tenant_id: str,
    alert: AlertData,
    secrets: TenantSecrets,
) -> EnrichedAlert:
    """
    Verrijkt een Defender-alert met gebruikers- en device-context uit Graph API.
    Later: GET /security/alerts/{alertId}, GET /users/{email}, GET /devices/{deviceId}.
    """
    activity.logger.info(
        f"[{tenant_id}] Graph: alert '{alert.alert_id}' verrijken"
    )

    # TODO: replace with real Graph API calls
    return EnrichedAlert(
        alert_id=alert.alert_id,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        user_display_name="Jan De Vries",
        user_department="Engineering",
        device_display_name="LAPTOP-SEC042",
        device_os="Windows 11 Enterprise",
        device_compliance="compliant",
    )


@activity.defn
async def graph_get_alerts(
    tenant_id: str,
    user_email: str,
    secrets: TenantSecrets,
) -> list[dict]:
    """
    Haalt recente security-alerts op voor een specifieke gebruiker.
    Later: GET /security/alerts?$filter=userStates/any(u:u/userPrincipalName eq '{email}').
    """
    activity.logger.info(
        f"[{tenant_id}] Graph: alerts ophalen voor gebruiker '{user_email}'"
    )

    # TODO: replace with real Graph API call
    return [
        {
            "alert_id": "alert-stub-001",
            "title": "Impossible travel activity",
            "severity": "high",
            "status": "new",
            "created": "2025-01-15T10:30:00Z",
        },
        {
            "alert_id": "alert-stub-002",
            "title": "Suspicious sign-in from unfamiliar location",
            "severity": "medium",
            "status": "new",
            "created": "2025-01-15T09:15:00Z",
        },
    ]


@activity.defn
async def graph_isolate_device(
    tenant_id: str,
    device_id: str,
    secrets: TenantSecrets,
) -> bool:
    """
    Isoleert een device via Microsoft Defender for Endpoint.
    Later: POST /security/tiIndicators of Defender ATP API.
    """
    activity.logger.info(
        f"[{tenant_id}] Graph: device '{device_id}' isoleren"
    )

    # TODO: replace with real Defender API call
    return True


@activity.defn
async def threat_intel_lookup(
    tenant_id: str,
    indicator: str,
) -> ThreatIntelResult:
    """
    Zoekt threat-intelligence informatie op voor een IP-adres of indicator.
    Later: koppeling met VirusTotal, AbuseIPDB of Microsoft TI API.
    """
    activity.logger.info(
        f"[{tenant_id}] Threat intel lookup voor indicator '{indicator}'"
    )

    # TODO: replace with real threat intel API call
    return ThreatIntelResult(
        indicator=indicator,
        is_malicious=True,
        provider="stub-threatintel",
        reputation_score=78.5,
        details="Known malicious IP associated with credential phishing campaigns.",
    )


@activity.defn
async def calculate_risk_score(
    tenant_id: str,
    enriched_alert: EnrichedAlert,
    threat_intel: ThreatIntelResult,
) -> RiskScore:
    """
    Berekent een risicoscore op basis van de verrijkte alert en threat intel.
    Later: uitbreiden met ML-model of score-matrix.
    """
    activity.logger.info(
        f"[{tenant_id}] Risicoscore berekenen voor alert '{enriched_alert.alert_id}'"
    )

    # Simpele score-logica voor PoC
    base_score = {"low": 20.0, "medium": 40.0, "high": 70.0, "critical": 90.0}.get(
        enriched_alert.severity, 50.0
    )

    factors: list[str] = []

    if threat_intel.is_malicious:
        base_score += 15.0
        factors.append("IP listed as malicious in threat intel")

    if threat_intel.reputation_score > 70:
        base_score += 5.0
        factors.append(f"High threat intel reputation score ({threat_intel.reputation_score})")

    if enriched_alert.device_compliance != "compliant":
        base_score += 10.0
        factors.append("Device is non-compliant")

    score = min(base_score, 100.0)
    level = (
        "critical" if score >= 80
        else "high" if score >= 60
        else "medium" if score >= 40
        else "low"
    )

    return RiskScore(
        alert_id=enriched_alert.alert_id,
        score=score,
        level=level,
        factors=factors,
    )
