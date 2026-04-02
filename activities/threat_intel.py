from __future__ import annotations

import asyncio
from urllib.parse import quote

import httpx
from temporalio import activity

from activities._activity_errors import application_error_from_http_status
from activities._tenant_secrets import load_tenant_secrets
from connectors.registry import get_connector
from shared.models import ThreatIntelResult
from shared.providers.types import secret_type_for_provider
from shared.ssm_client import get_secret


def _handle_http_error(tenant_id: str, provider: str, status: int, action: str) -> None:
    if status >= 400:
        raise application_error_from_http_status(tenant_id, provider, action, status)


@activity.defn
async def threat_intel_fanout(
    tenant_id: str,
    providers: list[str],
    indicator: str,
) -> ThreatIntelResult:
    """Fan-out threat-intel lookups and keep the strongest reputation score."""
    activity.logger.info(
        "[%s] threat_intel_fanout indicator=%s providers=%s",
        tenant_id,
        indicator,
        providers,
    )

    best = ThreatIntelResult(
        indicator=indicator,
        is_malicious=False,
        provider="none",
        reputation_score=0.0,
        details="No provider returned a positive result.",
    )

    for provider in providers:
        try:
            secret_type = secret_type_for_provider(provider)
            secrets = load_tenant_secrets(tenant_id, secret_type)
            connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
            response = await connector.execute_action("lookup_indicator", {"indicator": indicator})
            score = float(response.get("reputation_score", 0.0))
            if score > best.reputation_score:
                best = ThreatIntelResult(
                    indicator=indicator,
                    is_malicious=bool(response.get("is_malicious", False)),
                    provider=provider,
                    reputation_score=score,
                    details=str(response.get("details", "")),
                )
        except Exception as exc:
            activity.logger.warning(
                "[%s] threat_intel_fanout provider=%s failed: %s",
                tenant_id,
                provider,
                exc,
            )

    return best


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
