import re
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.subscription import subscription_create, subscription_list
    from shared.models import (
        OnboardingSubscriptionReconcileStageRequest,
        OnboardingSubscriptionReconcileStageResult,
    )
    from shared.models.subscriptions import SubscriptionState


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


def _resource_slug(resource: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", resource.strip().lower()).strip("-")
    return slug or "subscription"


@workflow.defn
class OnboardingSubscriptionReconcileStageWorkflow:
    """Ensure required Graph subscriptions exist for the onboarded tenant."""

    @workflow.run
    async def run(
        self,
        request: OnboardingSubscriptionReconcileStageRequest,
    ) -> OnboardingSubscriptionReconcileStageResult:
        config = request.config
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)
        notification_url = (request.notification_url or "").strip()

        created_subscription_ids: list[str] = []
        existing_keys: set[tuple[str, tuple[str, ...]]] = set()
        has_desired_graph_subscriptions = bool(config.graph_subscriptions)

        if has_desired_graph_subscriptions and notification_url:
            existing_subscriptions: list[SubscriptionState] = await workflow.execute_activity(
                subscription_list,
                args=[request.tenant_id, "graph"],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )

            existing_keys = {
                (state.resource, tuple(sorted(state.change_types)))
                for state in existing_subscriptions
            }

            for desired in config.graph_subscriptions:
                key = (desired.resource, tuple(sorted(desired.change_types)))
                if key in existing_keys:
                    continue

                try:
                    state: SubscriptionState = await workflow.execute_activity(
                        subscription_create,
                        args=[
                            request.tenant_id,
                            desired,
                            "graph",
                            notification_url,
                            f"secamo:{request.tenant_id}:{_resource_slug(desired.resource)}",
                        ],
                        start_to_close_timeout=TIMEOUT,
                        retry_policy=runtime_retry,
                    )
                    created_subscription_ids.append(state.subscription_id)
                    existing_keys.add(key)
                except Exception as exc:
                    workflow.logger.warning(
                        "Onboarding subscription reconcile: failed to create subscription for resource=%s reason=%s",
                        desired.resource,
                        exc,
                    )
        elif has_desired_graph_subscriptions and not notification_url:
            for desired in config.graph_subscriptions:
                workflow.logger.warning(
                    "Onboarding subscription reconcile: skipping subscription create for resource=%s reason=missing_notification_url",
                    desired.resource,
                )

        return OnboardingSubscriptionReconcileStageResult(
            created_subscription_ids=created_subscription_ids,
            active_subscription_count=len(existing_keys),
        )
