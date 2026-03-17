from __future__ import annotations

from temporalio import activity

from shared.models import EnrichedAlert, RiskScore, ThreatIntelResult


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
