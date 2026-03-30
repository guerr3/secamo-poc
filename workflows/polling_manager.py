from __future__ import annotations

from datetime import timedelta, timezone

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from activities.connector_dispatch import connector_fetch_events
    from activities.tenant import get_tenant_config
    from shared.models import PollingManagerInput, TenantConfig
    from shared.models.canonical import Envelope
    from shared.models.mappers import resolve_polling_route

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)

@workflow.defn
class PollingManagerWorkflow:
    """Long-running polling loop for a tenant/provider/resource tuple via continue-as-new."""

    @workflow.run
    async def run(self, input: PollingManagerInput) -> str:
        workflow.logger.info(
            "PollingManager iter=%s tenant=%s provider=%s resource_type=%s cursor=%s",
            input.iteration,
            input.tenant_id,
            input.provider,
            input.resource_type,
            input.cursor,
        )

        effective_secret_type = input.secret_type
        effective_poll_interval = input.poll_interval_seconds

        if input.iteration == 0:
            config: TenantConfig = await workflow.execute_activity(
                get_tenant_config,
                args=[input.tenant_id],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )

            provider_cfg = next(
                (
                    item
                    for item in config.polling_providers
                    if item.provider == input.provider and item.resource_type == input.resource_type
                ),
                None,
            )
            if provider_cfg is not None:
                effective_secret_type = provider_cfg.secret_type
                effective_poll_interval = provider_cfg.poll_interval_seconds

        fetch_result = await workflow.execute_activity(
            connector_fetch_events,
            args=[
                input.tenant_id,
                input.provider,
                {
                    "since": input.cursor,
                    "resource_type": input.resource_type,
                    "top": 100,
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        new_cursor = input.cursor
        for event in fetch_result.data.events:
            if event.occurred_at is not None:
                occurred = event.occurred_at
                if occurred.tzinfo is None:
                    occurred = occurred.replace(tzinfo=timezone.utc)
                else:
                    occurred = occurred.astimezone(timezone.utc)
                new_cursor = occurred.strftime("%Y-%m-%dT%H:%M:%SZ")

            route = resolve_polling_route(
                provider=input.provider,
                resource_type=input.resource_type,
                payload=event.payload,
            )
            if route is None:
                workflow.logger.warning(
                    "No polling route configured for provider=%s resource_type=%s event_id=%s",
                    input.provider,
                    input.resource_type,
                    event.event_id,
                )
                continue

            workflow_name, task_queue = route
            envelope = event
            event_id = envelope.event_id
            child_workflow_id = f"{input.provider}-{input.resource_type}-{input.tenant_id}-{event_id}"

            try:
                await workflow.start_child_workflow(
                    workflow_name,
                    envelope,
                    id=child_workflow_id,
                    task_queue=task_queue,
                    parent_close_policy=workflow.ParentClosePolicy.ABANDON,
                )
            except WorkflowAlreadyStartedError:
                workflow.logger.info("Duplicate event skipped via deterministic workflow_id=%s", child_workflow_id)

        await workflow.sleep(timedelta(seconds=effective_poll_interval))

        workflow.continue_as_new(
            PollingManagerInput(
                tenant_id=input.tenant_id,
                provider=input.provider,
                resource_type=input.resource_type,
                secret_type=effective_secret_type,
                poll_interval_seconds=effective_poll_interval,
                cursor=new_cursor,
                iteration=input.iteration + 1,
            )
        )

        return "continue-as-new"
