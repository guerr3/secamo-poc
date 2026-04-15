import re
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

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

        created_subscription_ids: list[str] = []
        existing_keys: set[tuple[str, tuple[str, ...]]] = set()
        has_desired_graph_subscriptions = bool(config.graph_subscriptions)

        if has_desired_graph_subscriptions and not request.notification_url:
            if request.partial_onboarding:
                workflow.logger.warning(
                    "Onboarding subscription reconcile in partial mode: graph notification URL missing; skipping graph subscription bootstrap"
                )
                return OnboardingSubscriptionReconcileStageResult(
                    created_subscription_ids=[],
                    active_subscription_count=0,
                )

            raise ApplicationError(
                "Graph notification URL could not be resolved during onboarding provisioning",
                type="MissingGraphNotificationUrl",
                non_retryable=True,
            )

        if has_desired_graph_subscriptions and request.notification_url:
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

                state: SubscriptionState = await workflow.execute_activity(
                    subscription_create,
                    args=[
                        request.tenant_id,
                        desired,
                        "graph",
                        request.notification_url,
                        f"secamo:{request.tenant_id}:{_resource_slug(desired.resource)}",
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                created_subscription_ids.append(state.subscription_id)
                existing_keys.add(key)

        return OnboardingSubscriptionReconcileStageResult(
            created_subscription_ids=created_subscription_ids,
            active_subscription_count=len(existing_keys),
        )
