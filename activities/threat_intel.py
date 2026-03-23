from __future__ import annotations

import asyncio
from urllib.parse import quote

import httpx
from temporalio import activity

from activities._activity_errors import application_error_from_http_status
from shared.models import ThreatIntelResult
from shared.ssm_client import get_secret


def _handle_http_error(tenant_id: str, provider: str, status: int, action: str) -> None:
    if status >= 400:
        raise application_error_from_http_status(tenant_id, provider, action, status)


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

    api_key = await asyncio.to_thread(get_secret, tenant_id, "threatintel/virustotal_api_key")
    if not api_key:
        api_key = await asyncio.to_thread(get_secret, tenant_id, "threatintel/api_key")
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
        raise application_error_from_http_status(
            tenant_id,
            "virustotal",
            "threat_intel_lookup",
            response.status_code,
        )

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
