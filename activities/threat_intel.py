from __future__ import annotations

import asyncio
from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._activity_errors import application_error_from_http_status
from activities.tenant import get_tenant_config
from shared.models import ThreatIntelResult
from shared.providers.factory import get_threat_intel_provider
from shared.providers.threat_intel import ThreatIntelHttpStatusError
from shared.providers.types import secret_type_for_provider
from shared.ssm_client import get_secret_bundle


def _resolve_default_provider(providers: list[str]) -> str:
    for provider in providers:
        normalized = str(provider).strip().lower()
        if normalized:
            return normalized
    return "virustotal"


async def _load_secret_bundle_async(tenant_id: str, secret_type: str) -> dict[str, str]:
    return await asyncio.to_thread(get_secret_bundle, tenant_id, secret_type)


async def _get_provider(tenant_id: str, *, default_provider: str | None = None):
    provider_name = default_provider
    if not provider_name:
        config = await get_tenant_config(tenant_id)
        provider_name = _resolve_default_provider(list(config.threat_intel_providers))

    try:
        secret_type = secret_type_for_provider(provider_name)
    except ValueError:
        secret_type = "threatintel"

    secrets = await _load_secret_bundle_async(tenant_id, secret_type)
    return await get_threat_intel_provider(
        tenant_id,
        secrets,
        default_provider=provider_name,
    )


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

    provider = await _get_provider(
        tenant_id,
        default_provider=_resolve_default_provider(providers),
    )
    return await provider.fanout(indicator, providers)


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

    try:
        provider = await _get_provider(tenant_id)
        return await provider.lookup_indicator(indicator)
    except ThreatIntelHttpStatusError as exc:
        raise application_error_from_http_status(
            tenant_id,
            exc.provider,
            exc.action,
            exc.status_code,
        ) from exc
    except ValueError as exc:
        raise ApplicationError(
            f"[{tenant_id}] threat_intel_lookup configuration error: {exc}",
            type="ThreatIntelConfigError",
            non_retryable=True,
        ) from exc
