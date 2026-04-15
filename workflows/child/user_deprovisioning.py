from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.identity import identity_revoke_sessions, identity_update_user
    from shared.models import UserDeprovisioningRequest

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class UserDeprovisioningWorkflow:
    """Reusable child workflow for user offboarding (session revoke + disable)."""

    @workflow.run
    async def run(self, request: UserDeprovisioningRequest) -> bool:
        workflow.logger.info(
            "UserDeprovisioningWorkflow gestart — tenant=%s user=%s",
            request.tenant_id,
            request.user_email,
        )

        await workflow.execute_activity(
            identity_revoke_sessions,
            args=[request.tenant_id, request.user_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
        disabled = await workflow.execute_activity(
            identity_update_user,
            args=[request.tenant_id, request.user_id, {"accountEnabled": False}],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        return bool(disabled)
