from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

from activities.tenant import get_tenant_config, validate_tenant_context
from shared.models import TenantConfig


async def bootstrap_tenant(
    tenant_id: str,
    retry_policy: RetryPolicy,
    timeout: timedelta,
) -> TenantConfig:
    """Validate tenant and fetch runtime config without loading tenant secrets."""
    await workflow.execute_activity(
        validate_tenant_context,
        args=[tenant_id],
        start_to_close_timeout=timeout,
        retry_policy=retry_policy,
    )

    return await workflow.execute_activity(
        get_tenant_config,
        args=[tenant_id],
        start_to_close_timeout=timeout,
        retry_policy=retry_policy,
    )
