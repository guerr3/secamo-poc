from __future__ import annotations

import asyncio
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.tenant import get_tenant_config
from shared.models import TriageRequest, TriageResult
from shared.providers.factory import get_ai_provider
from shared.ssm_client import get_secret_bundle


def _secret_type_from_credentials_path(path_template: str) -> str:
    """Extract SSM secret_type from a configured credentials path template."""
    normalized = path_template.replace("{tenant_id}", "tenant-placeholder").strip("/")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return "ai_triage"
    return parts[-1]


async def _load_secret_bundle_async(tenant_id: str, secret_type: str) -> dict[str, str]:
    """Load tenant secret bundle via thread offloading for boto3-backed calls."""
    return await asyncio.to_thread(get_secret_bundle, tenant_id, secret_type)


@activity.defn
async def perform_ai_triage(
    tenant_id: str,
    raw_alert_data: dict[str, Any],
    alert_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> TriageResult:
    """Perform provider-agnostic AI triage for one tenant alert payload.

    This activity is intentionally thin:
    1. Resolve tenant config.
    2. Load tenant-scoped secrets.
    3. Resolve provider via factory.
    4. Execute provider protocol method.
    """
    cfg = await get_tenant_config(tenant_id)
    if not cfg.ai_triage_config.enabled:
        raise ApplicationError(
            f"AI triage is disabled for tenant '{tenant_id}'",
            type="AITriageDisabled",
            non_retryable=True,
        )

    secret_type = _secret_type_from_credentials_path(cfg.ai_triage_config.credentials_path)
    secrets = await _load_secret_bundle_async(tenant_id, secret_type)
    if not secrets:
        raise ApplicationError(
            f"No AI triage secrets found for tenant '{tenant_id}' and secret_type '{secret_type}'",
            type="MissingTenantSecrets",
            non_retryable=True,
        )

    provider = await get_ai_provider(tenant_id, secrets)
    request = TriageRequest(
        tenant_id=tenant_id,
        alert_id=alert_id,
        alert_data=raw_alert_data,
        context=context or {},
    )

    activity.logger.info(
        "[%s] perform_ai_triage provider=%s alert_id=%s",
        tenant_id,
        cfg.ai_triage_config.provider_type,
        alert_id,
    )
    return await provider.analyze_alert(request)
