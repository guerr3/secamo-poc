from __future__ import annotations

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._tenant_secrets import load_tenant_secrets
from connectors.errors import ConnectorPermanentError, ConnectorTransientError
from connectors.registry import get_connector
from shared.models import (
    ConnectorActionData,
    ConnectorActionResult,
    ConnectorFetchData,
    ConnectorFetchResult,
    ConnectorHealthData,
    ConnectorHealthResult,
    ThreatIntelResult,
)
from shared.providers.types import secret_type_for_provider


def _raise_connector_activity_error(operation: str, provider: str, error: Exception) -> None:
    """Translate connector errors into explicit Temporal retry semantics."""
    message = f"connector {operation} failed for provider '{provider}': {error}"

    if isinstance(error, ConnectorPermanentError):
        raise ApplicationError(
            message,
            type="ConnectorPermanentError",
            non_retryable=True,
        ) from error

    if isinstance(error, ConnectorTransientError):
        raise ApplicationError(
            message,
            type="ConnectorTransientError",
            non_retryable=False,
        ) from error

    raise ApplicationError(
        message,
        type="ConnectorActivityError",
        non_retryable=False,
    ) from error


def _load_connector(tenant_id: str, provider: str):
    secret_type = secret_type_for_provider(provider)
    secrets = load_tenant_secrets(tenant_id, secret_type)
    return get_connector(provider=provider, tenant_id=tenant_id, secrets=secrets)


@activity.defn
async def connector_fetch_events(
    tenant_id: str,
    provider: str,
    query: dict,
) -> ConnectorFetchResult:
    activity.logger.info("[%s] Connector fetch events via provider '%s'", tenant_id, provider)
    try:
        connector = _load_connector(tenant_id, provider)
        events = await connector.fetch_events(query)
        return ConnectorFetchResult(
            provider=provider,
            success=True,
            details="fetch completed",
            data=ConnectorFetchData(events=events, raw_count=len(events)),
        )
    except Exception as exc:
        activity.logger.exception(
            "[%s] Connector fetch events failed for provider '%s'",
            tenant_id,
            provider,
        )
        _raise_connector_activity_error("fetch_events", provider, exc)


@activity.defn
async def connector_execute_action(
    tenant_id: str,
    provider: str,
    action: str,
    payload: dict,
) -> ConnectorActionResult:
    activity.logger.info("[%s] Connector action '%s' via provider '%s'", tenant_id, action, provider)
    try:
        connector = _load_connector(tenant_id, provider)
        data = await connector.execute_action(action=action, payload=payload)

        success = not (isinstance(data, dict) and data.get("success") is False)
        details = "action completed"
        if isinstance(data, dict):
            details = str(data.get("details") or data.get("reason") or details)

        if not success:
            retryable = bool(isinstance(data, dict) and data.get("retryable") is True)
            raise ApplicationError(
                f"connector action '{action}' reported failure for provider '{provider}': {details}",
                type="ConnectorActionReportedFailure",
                non_retryable=not retryable,
            )

        return ConnectorActionResult(
            provider=provider,
            operation_type="action",
            success=True,
            details=details,
            data=ConnectorActionData(action=action, payload=data if isinstance(data, dict) else {}),
        )
    except ApplicationError:
        raise
    except Exception as exc:
        activity.logger.exception(
            "[%s] Connector action '%s' failed for provider '%s'",
            tenant_id,
            action,
            provider,
        )
        _raise_connector_activity_error("execute_action", provider, exc)


@activity.defn
async def connector_health_check(
    tenant_id: str,
    provider: str,
) -> ConnectorHealthResult:
    activity.logger.info("[%s] Connector health check via provider '%s'", tenant_id, provider)
    try:
        connector = _load_connector(tenant_id, provider)
        result = await connector.health_check()
        return ConnectorHealthResult(
            provider=provider,
            success=bool(result.get("healthy", False)),
            details=str(result),
            data=ConnectorHealthData(healthy=bool(result.get("healthy", False))),
        )
    except Exception as exc:
        activity.logger.exception(
            "[%s] Connector health check failed for provider '%s'",
            tenant_id,
            provider,
        )
        _raise_connector_activity_error("health_check", provider, exc)


@activity.defn
async def connector_threat_intel_fanout(
    tenant_id: str,
    providers: list[str],
    indicator: str,
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
        try:
            connector = _load_connector(tenant_id, provider)
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
        except Exception as exc:
            activity.logger.warning(
                "[%s] Threat-intel lookup failed for provider '%s': %s",
                tenant_id,
                provider,
                exc,
            )

    return best
