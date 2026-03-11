from __future__ import annotations

from temporalio import activity

from connectors.registry import get_connector
from shared.models import (
    CanonicalEvent,
    ConnectorActionResult,
    ConnectorFetchResult,
    ConnectorHealthResult,
    TenantSecrets,
    ThreatIntelResult,
)


@activity.defn
async def connector_fetch_events(
    tenant_id: str,
    provider: str,
    query: dict,
    secrets: TenantSecrets,
) -> ConnectorFetchResult:
    activity.logger.info("[%s] Connector fetch events via provider '%s'", tenant_id, provider)
    connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
    events = await connector.fetch_events(query)
    return ConnectorFetchResult(provider=provider, events=events, raw_count=len(events))


@activity.defn
async def connector_execute_action(
    tenant_id: str,
    provider: str,
    action: str,
    payload: dict,
    secrets: TenantSecrets,
) -> ConnectorActionResult:
    activity.logger.info("[%s] Connector action '%s' via provider '%s'", tenant_id, action, provider)
    connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
    data = await connector.execute_action(action=action, payload=payload)
    return ConnectorActionResult(
        provider=provider,
        action=action,
        success=True,
        details="action completed",
        data=data,
    )


@activity.defn
async def connector_health_check(
    tenant_id: str,
    provider: str,
    secrets: TenantSecrets,
) -> ConnectorHealthResult:
    activity.logger.info("[%s] Connector health check via provider '%s'", tenant_id, provider)
    connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
    result = await connector.health_check()
    return ConnectorHealthResult(
        provider=provider,
        healthy=bool(result.get("healthy", False)),
        details=str(result),
    )


@activity.defn
async def connector_threat_intel_fanout(
    tenant_id: str,
    providers: list[str],
    indicator: str,
    secrets: TenantSecrets,
) -> ThreatIntelResult:
    """Fan-out TI lookups; return the strongest malicious score."""
    activity.logger.info(
        "[%s] Threat-intel fanout for indicator '%s' across %s",
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
        connector = get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)
        response = await connector.execute_action("lookup_indicator", {"indicator": indicator})
        score = float(response.get("reputation_score", 0.0))
        if score > best.reputation_score:
            best = ThreatIntelResult(
                indicator=indicator,
                is_malicious=bool(response.get("is_malicious", False)),
                provider=provider,
                reputation_score=score,
                details=response.get("details", ""),
            )

    return best
