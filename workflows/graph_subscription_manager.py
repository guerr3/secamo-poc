from __future__ import annotations

from datetime import timedelta
from typing import Iterable

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.graph_subscriptions import (
        create_graph_subscription,
        delete_graph_subscription,
        load_subscription_metadata,
        renew_graph_subscription,
    )
    from activities.tenant import get_tenant_config
    from shared.models import (
        GraphSubscriptionConfig,
        GraphSubscriptionManagerInput,
        GraphSubscriptionState,
        TenantConfig,
    )

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
RENEW_WINDOW = timedelta(minutes=30)
DEFAULT_IDLE_SLEEP = timedelta(minutes=15)


@workflow.defn
class GraphSubscriptionManagerWorkflow:
    """Long-running tenant workflow that reconciles Graph webhook subscriptions."""

    def __init__(self) -> None:
        self._subscription_list_changed = False
        self._offboard_tenant = False

    @workflow.signal
    def subscription_list_changed(self) -> None:
        self._subscription_list_changed = True

    @workflow.signal
    def offboard_tenant(self) -> None:
        self._offboard_tenant = True

    @workflow.run
    async def run(self, input: GraphSubscriptionManagerInput) -> str:
        config: TenantConfig = await workflow.execute_activity(
            get_tenant_config,
            args=[input.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        current = await workflow.execute_activity(
            load_subscription_metadata,
            args=[input.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        desired = config.graph_subscriptions
        current_by_resource = {item.resource: item for item in current}

        for desired_subscription in desired:
            if desired_subscription.resource in current_by_resource:
                continue

            created: GraphSubscriptionState = await workflow.execute_activity(
                create_graph_subscription,
                args=[
                    input.tenant_id,
                    desired_subscription,
                    input.secret_type,
                    input.notification_url,
                    self._client_state(input.tenant_id, desired_subscription),
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            current_by_resource[created.resource] = created

        stale_resources = set(current_by_resource.keys()) - {item.resource for item in desired}
        for resource in stale_resources:
            stale = current_by_resource[resource]
            await workflow.execute_activity(
                delete_graph_subscription,
                args=[input.tenant_id, stale.subscription_id, input.secret_type],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            current_by_resource.pop(resource, None)

        if self._offboard_tenant:
            for subscription in current_by_resource.values():
                await workflow.execute_activity(
                    delete_graph_subscription,
                    args=[input.tenant_id, subscription.subscription_id, input.secret_type],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
            return "offboarded"

        now = workflow.now()
        renewal_deadline = now + RENEW_WINDOW
        for desired_subscription in desired:
            state = current_by_resource.get(desired_subscription.resource)
            if state is None:
                continue
            if state.expires_at <= renewal_deadline:
                renewed = await workflow.execute_activity(
                    renew_graph_subscription,
                    args=[
                        input.tenant_id,
                        state.subscription_id,
                        desired_subscription.expiration_hours,
                        input.secret_type,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
                current_by_resource[state.resource] = renewed

        wait_duration = self._next_wait_duration(current_by_resource.values(), now)
        await workflow.wait_condition(
            lambda: self._offboard_tenant or self._subscription_list_changed,
            timeout=wait_duration,
        )

        await workflow.wait_condition(workflow.all_handlers_finished)
        workflow.continue_as_new(
            GraphSubscriptionManagerInput(
                tenant_id=input.tenant_id,
                notification_url=input.notification_url,
                secret_type=input.secret_type,
                iteration=input.iteration + 1,
            )
        )

        return "continue-as-new"

    def _next_wait_duration(
        self,
        subscriptions: Iterable[GraphSubscriptionState],
        now,
    ) -> timedelta:
        items = list(subscriptions)
        if not items:
            return DEFAULT_IDLE_SLEEP

        next_renew_at = min(item.expires_at for item in items) - RENEW_WINDOW
        delta = next_renew_at - now
        if delta <= timedelta(seconds=0):
            return timedelta(seconds=5)
        if delta > timedelta(hours=6):
            return timedelta(hours=6)
        return delta

    def _client_state(self, tenant_id: str, subscription: GraphSubscriptionConfig) -> str:
        safe_resource = subscription.resource.replace("/", "-")
        return f"secamo:{tenant_id}:{safe_resource}"
