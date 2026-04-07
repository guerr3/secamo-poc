from __future__ import annotations

from typing import Any

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
    """Threat-intel provider backed by connector actions."""

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

    async def lookup_indicator(
        self,
        indicator: str,
        *,
        provider_override: str | None = None,
    ) -> ThreatIntelResult:
        provider = (provider_override or self._default_provider).strip().lower() or "virustotal"
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
