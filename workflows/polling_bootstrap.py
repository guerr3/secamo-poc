from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.tenant import get_all_active_tenants, get_tenant_config
    from shared.config import QUEUE_POLLING
    from shared.models import PollingBootstrapInput, PollingManagerInput, TenantConfig
    from shared.workflow_helpers import start_child_workflow_idempotent
    from workflows.polling_manager import PollingManagerWorkflow


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class PollingBootstrapWorkflow:
    """Operational workflow to (re)concile polling manager workflows per tenant."""

    @workflow.run
    async def run(self, input: PollingBootstrapInput) -> str:
        if input.tenant_id:
            tenant_ids = [input.tenant_id]
        else:
            active_tenants = await workflow.execute_activity(
                get_all_active_tenants,
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            tenant_ids = sorted(
                {
                    str(item.get("tenant_id") or "").strip()
                    for item in active_tenants
                    if str(item.get("tenant_id") or "").strip()
                }
            )

        if not tenant_ids:
            workflow.logger.warning("PollingBootstrap found no tenants to reconcile")
            return "Polling bootstrap skipped: no active tenants"

        started_children = 0
        duplicate_provider_configs = 0
        for tenant_id in tenant_ids:
            config: TenantConfig = await workflow.execute_activity(
                get_tenant_config,
                args=[tenant_id],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )

            seen_provider_resources: set[tuple[str, str]] = set()
            for provider_cfg in config.polling_providers:
                provider_resource = (provider_cfg.provider, provider_cfg.resource_type)
                if provider_resource in seen_provider_resources:
                    duplicate_provider_configs += 1
                    continue
                seen_provider_resources.add(provider_resource)

                polling_workflow_id = (
                    f"polling-{tenant_id}-{provider_cfg.provider}-{provider_cfg.resource_type}"
                )
                await start_child_workflow_idempotent(
                    PollingManagerWorkflow.run,
                    PollingManagerInput(
                        tenant_id=tenant_id,
                        provider=provider_cfg.provider,
                        resource_type=provider_cfg.resource_type,
                        secret_type=provider_cfg.secret_type,
                        poll_interval_seconds=provider_cfg.poll_interval_seconds,
                        cursor=None,
                        iteration=0,
                    ),
                    workflow_id=polling_workflow_id,
                    task_queue=QUEUE_POLLING,
                    parent_close_policy=workflow.ParentClosePolicy.ABANDON,
                )
                started_children += 1

        return (
            f"Polling bootstrap reconciled {started_children} polling managers "
            f"across {len(tenant_ids)} tenant(s). "
            f"Skipped duplicate provider configs: {duplicate_provider_configs}."
        )
