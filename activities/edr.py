"""EDR domain activities.

Thin @activity.defn functions for EDR operations. Each function:
  1. Loads tenant config + secrets
  2. Calls the EDR provider factory
  3. Translates ConnectorPermanentError/ConnectorTransientError to ApplicationError
"""

from __future__ import annotations

from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._tenant_secrets import load_tenant_secrets
from activities.tenant import get_tenant_config
from connectors.errors import ConnectorPermanentError, ConnectorTransientError
from shared.models import (
    AlertEnrichmentResult,
    AlertSummary,
    ConnectorActionResult,
    ConnectorFetchData,
    ConnectorFetchResult,
    DeviceContext,
    SignInEvent,
)
from shared.providers.factory import get_edr_provider
from shared.providers.types import secret_type_for_provider


def _raise_edr_error(operation: str, error: Exception) -> None:
    """Translate connector errors into explicit Temporal retry semantics."""
    message = f"EDR {operation} failed: {error}"
    if isinstance(error, ConnectorPermanentError):
        raise ApplicationError(message, type="ConnectorPermanentError", non_retryable=True) from error
    if isinstance(error, ConnectorTransientError):
        raise ApplicationError(message, type="ConnectorTransientError", non_retryable=False) from error
    raise ApplicationError(message, type="EDRActivityError", non_retryable=False) from error


async def _get_provider(tenant_id: str, *, provider_override: str | None = None):
    config = await get_tenant_config(tenant_id)
    provider_name = provider_override or config.edr_provider
    secret_type = secret_type_for_provider(provider_name)
    secrets = load_tenant_secrets(tenant_id, secret_type)
    return await get_edr_provider(tenant_id, secrets, provider=provider_name)


@activity.defn
async def edr_fetch_events(tenant_id: str, query: dict[str, Any]) -> ConnectorFetchResult:
    """Fetch provider events through the EDR capability surface."""
    provider_name = str(query.get("provider") or "").strip() or None
    activity.logger.info("[%s] edr_fetch_events provider=%s", tenant_id, provider_name or "default")
    try:
        provider = await _get_provider(tenant_id, provider_override=provider_name)
        events = await provider.fetch_events(query)
        return ConnectorFetchResult(
            provider=provider_name or "edr",
            success=True,
            details="fetch completed",
            data=ConnectorFetchData(events=events, raw_count=len(events)),
        )
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("fetch_events", exc)


@activity.defn
async def edr_enrich_alert(
    tenant_id: str,
    alert_id: str,
    context: dict[str, Any] | None = None,
) -> AlertEnrichmentResult:
    """Enrich an alert via the EDR provider."""
    activity.logger.info("[%s] edr_enrich_alert alert=%s", tenant_id, alert_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.enrich_alert(alert_id, context)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("enrich_alert", exc)


@activity.defn
async def edr_get_device_context(tenant_id: str, device_id: str) -> DeviceContext | None:
    """Get device context via the EDR provider."""
    activity.logger.info("[%s] edr_get_device_context device=%s", tenant_id, device_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.get_device_context(device_id)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("get_device_context", exc)


@activity.defn
async def edr_isolate_device(tenant_id: str, device_id: str) -> ConnectorActionResult:
    """Isolate a device via the EDR provider."""
    activity.logger.info("[%s] edr_isolate_device device=%s", tenant_id, device_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.isolate_device(device_id, "Isolated by Secamo orchestrator")
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("isolate_device", exc)


@activity.defn
async def edr_unisolate_device(tenant_id: str, device_id: str) -> ConnectorActionResult:
    """Release a device from isolation via the EDR provider."""
    activity.logger.info("[%s] edr_unisolate_device device=%s", tenant_id, device_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.unisolate_device(device_id, "Released from isolation by Secamo orchestrator")
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("unisolate_device", exc)


@activity.defn
async def edr_run_antivirus_scan(
    tenant_id: str,
    device_id: str,
    scan_type: str = "Quick",
) -> ConnectorActionResult:
    """Run an antivirus scan via the EDR provider."""
    activity.logger.info("[%s] edr_run_antivirus_scan device=%s", tenant_id, device_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.run_antivirus_scan(device_id, scan_type)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("run_antivirus_scan", exc)


@activity.defn
async def edr_list_noncompliant_devices(tenant_id: str) -> list[DeviceContext]:
    """List noncompliant devices via the EDR provider."""
    activity.logger.info("[%s] edr_list_noncompliant_devices", tenant_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.list_noncompliant_devices()
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("list_noncompliant_devices", exc)


@activity.defn
async def edr_get_user_alerts(tenant_id: str, user_email: str) -> list[AlertSummary]:
    """Get recent alerts for a user via the EDR provider."""
    activity.logger.info("[%s] edr_get_user_alerts user=%s", tenant_id, user_email)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.get_user_alerts(user_email)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("get_user_alerts", exc)


@activity.defn
async def edr_get_signin_history(
    tenant_id: str,
    user_principal_name: str,
    top: int = 20,
) -> list[SignInEvent]:
    """Get sign-in history for a user via the EDR provider."""
    activity.logger.info("[%s] edr_get_signin_history user=%s", tenant_id, user_principal_name)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.get_signin_history(user_principal_name, top)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("get_signin_history", exc)


