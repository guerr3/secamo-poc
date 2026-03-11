from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

from activities.tenant import get_tenant_config, get_tenant_secrets, validate_tenant_context
from shared.models import TenantConfig, TenantSecrets


async def bootstrap_tenant(
    tenant_id: str,
    retry_policy: RetryPolicy,
    timeout: timedelta,
    secret_type: str = "graph",
) -> tuple[TenantConfig, TenantSecrets]:
    """Validate tenant and fetch both config and secrets for workflow bootstrap."""
    await workflow.execute_activity(
        validate_tenant_context,
        args=[tenant_id],
        start_to_close_timeout=timeout,
        retry_policy=retry_policy,
    )

    config_future = workflow.execute_activity(
        get_tenant_config,
        args=[tenant_id],
        start_to_close_timeout=timeout,
        retry_policy=retry_policy,
    )
    secrets_future = workflow.execute_activity(
        get_tenant_secrets,
        args=[tenant_id, secret_type],
        start_to_close_timeout=timeout,
        retry_policy=retry_policy,
    )

    config, secrets = await asyncio.gather(config_future, secrets_future)
    return config, secrets
