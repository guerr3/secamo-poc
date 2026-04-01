"""EDR domain activities.

Thin @activity.defn functions for EDR operations. Each function:
  1. Loads tenant config + secrets
  2. Calls the EDR provider factory
  3. Translates ConnectorPermanentError/ConnectorTransientError to ApplicationError
"""

from __future__ import annotations

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities._tenant_secrets import load_tenant_secrets
from activities.tenant import get_tenant_config
from connectors.errors import ConnectorPermanentError, ConnectorTransientError
from shared.models import ConnectorActionData, ConnectorActionResult, DeviceContext, IdentityRiskContext
from shared.providers.edr import get_edr_provider
from shared.providers.types import secret_type_for_provider


def _raise_edr_error(operation: str, error: Exception) -> None:
    """Translate connector errors into explicit Temporal retry semantics."""
    message = f"EDR {operation} failed: {error}"
    if isinstance(error, ConnectorPermanentError):
        raise ApplicationError(message, type="ConnectorPermanentError", non_retryable=True) from error
    if isinstance(error, ConnectorTransientError):
        raise ApplicationError(message, type="ConnectorTransientError", non_retryable=False) from error
    raise ApplicationError(message, type="EDRActivityError", non_retryable=False) from error


async def _get_provider(tenant_id: str):
    config = await get_tenant_config(tenant_id)
    secret_type = secret_type_for_provider(config.edr_provider)
    secrets = load_tenant_secrets(tenant_id, secret_type)
    return get_edr_provider(tenant_id, secrets, provider=config.edr_provider)


@activity.defn
async def edr_enrich_alert(tenant_id: str, alert_id: str, context: dict | None = None) -> dict:
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
async def edr_isolate_device(tenant_id: str, device_id: str) -> bool:
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
async def edr_unisolate_device(tenant_id: str, device_id: str) -> bool:
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
        result = await provider.run_antivirus_scan(device_id, scan_type)
        submitted = bool(result.get("submitted", False))
        found = result.get("found") is not False
        return ConnectorActionResult(
            provider="edr",
            operation_type="action",
            success=submitted and found,
            details="scan action submitted" if submitted else "device not found",
            data=ConnectorActionData(action="run_antivirus_scan", payload=result),
        )
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("run_antivirus_scan", exc)


@activity.defn
async def edr_list_noncompliant_devices(tenant_id: str) -> list[dict]:
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
async def edr_get_user_alerts(tenant_id: str, user_email: str) -> list[dict]:
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
async def edr_confirm_user_compromised(tenant_id: str, user_id: str) -> bool:
    """Confirm a user as compromised via the EDR provider."""
    activity.logger.info("[%s] edr_confirm_user_compromised user=%s", tenant_id, user_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.confirm_user_compromised(user_id)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("confirm_user_compromised", exc)


@activity.defn
async def edr_dismiss_risky_user(tenant_id: str, user_id: str) -> bool:
    """Dismiss a risky user via the EDR provider."""
    activity.logger.info("[%s] edr_dismiss_risky_user user=%s", tenant_id, user_id)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.dismiss_risky_user(user_id)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("dismiss_risky_user", exc)


@activity.defn
async def edr_get_signin_history(
    tenant_id: str,
    user_principal_name: str,
    top: int = 20,
) -> list[dict]:
    """Get sign-in history for a user via the EDR provider."""
    activity.logger.info("[%s] edr_get_signin_history user=%s", tenant_id, user_principal_name)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.get_signin_history(user_principal_name, top)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("get_signin_history", exc)


@activity.defn
async def edr_list_risky_users(tenant_id: str, min_risk_level: str) -> list[dict]:
    """List risky users via the EDR provider."""
    activity.logger.info("[%s] edr_list_risky_users min_level=%s", tenant_id, min_risk_level)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.list_risky_users(min_risk_level)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("list_risky_users", exc)


@activity.defn
async def edr_get_identity_risk(tenant_id: str, lookup_key: str) -> IdentityRiskContext | None:
    """Get identity risk context via the EDR provider."""
    activity.logger.info("[%s] edr_get_identity_risk key=%s", tenant_id, lookup_key)
    try:
        provider = await _get_provider(tenant_id)
        return await provider.get_identity_risk(lookup_key)
    except ApplicationError:
        raise
    except Exception as exc:
        _raise_edr_error("get_identity_risk", exc)
