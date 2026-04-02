from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from connectors.registry import get_connector
from shared.models import ThreatIntelResult
from shared.providers.contracts import TenantSecrets


class ThreatIntelHttpStatusError(RuntimeError):
    """HTTP failure raised by threat-intel providers with status context."""

    def __init__(self, provider: str, action: str, status_code: int) -> None:
        super().__init__(f"{provider} {action} failed with status={status_code}")
        self.provider = provider
        self.action = action
        self.status_code = status_code


class ConnectorThreatIntelProvider:
    """Threat-intel provider backed by connector actions and direct VirusTotal fallback."""

    def __init__(
        self,
        *,
        tenant_id: str,
        secrets: TenantSecrets,
        default_provider: str = "virustotal",
    ) -> None:
        self._tenant_id = tenant_id
        self._secrets = secrets
        self._default_provider = default_provider.strip().lower() or "virustotal"

    @staticmethod
    def _result_from_payload(
        indicator: str,
        provider: str,
        payload: dict[str, Any],
    ) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            is_malicious=bool(payload.get("is_malicious", False)),
            provider=provider,
            reputation_score=float(payload.get("reputation_score", 0.0)),
            details=str(payload.get("details", "")),
        )

    async def _lookup_via_connector(self, provider: str, indicator: str) -> ThreatIntelResult:
        connector = get_connector(provider=provider, tenant_id=self._tenant_id, secrets=self._secrets)
        response = await connector.execute_action("lookup_indicator", {"indicator": indicator})
        payload = response if isinstance(response, dict) else {}
        return self._result_from_payload(indicator, provider, payload)

    async def _lookup_virustotal_http(self, indicator: str) -> ThreatIntelResult:
        api_key = self._secrets.virustotal_api_key
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

        if response.status_code != 200:
            raise ThreatIntelHttpStatusError("virustotal", "lookup_indicator", response.status_code)

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

    async def lookup_indicator(
        self,
        indicator: str,
        *,
        provider_override: str | None = None,
    ) -> ThreatIntelResult:
        provider = (provider_override or self._default_provider).strip().lower() or "virustotal"

        if provider == "virustotal":
            return await self._lookup_virustotal_http(indicator)

        return await self._lookup_via_connector(provider, indicator)

    async def fanout(self, indicator: str, providers: list[str]) -> ThreatIntelResult:
        best = ThreatIntelResult(
            indicator=indicator,
            is_malicious=False,
            provider="none",
            reputation_score=0.0,
            details="No provider returned a positive result.",
        )

        for provider in providers:
            provider_name = provider.strip().lower()
            if not provider_name:
                continue
            try:
                result = await self.lookup_indicator(indicator, provider_override=provider_name)
                if result.reputation_score > best.reputation_score:
                    best = result
            except Exception:
                continue

        return best
