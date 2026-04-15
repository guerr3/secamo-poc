import asyncio
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from activities.communications import email_send, teams_send_notification
    from shared.config import QUEUE_INTERACTIONS
    from shared.models import (
        OnboardingCommunicationsStageRequest,
        OnboardingCommunicationsStageResult,
        TicketResult,
    )
    from shared.workflow_helpers import create_soc_ticket


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class OnboardingCommunicationsStageWorkflow:
    """Send onboarding notifications and create the SOC onboarding ticket."""

    @workflow.run
    async def run(self, request: OnboardingCommunicationsStageRequest) -> OnboardingCommunicationsStageResult:
        runtime_retry = RetryPolicy(maximum_attempts=request.config.max_activity_attempts)

        teams_message = (
            f"Customer onboarding completed for tenant {request.tenant_id} ({request.display_name}). "
            f"Subscriptions created: {len(request.created_subscription_ids)}"
        )
        welcome_subject = f"Welcome to Secamo, {request.display_name}"
        welcome_body = (
            f"Hello,\n\n"
            f"Your Secamo onboarding for tenant '{request.tenant_id}' is completed.\n"
            f"SLA tier: {request.config.sla_tier}\n"
            f"Security subscriptions active: {request.active_subscription_count}\n\n"
            f"Regards,\nSecamo MSSP"
        )

        teams_task = workflow.execute_activity(
            teams_send_notification,
            args=[request.tenant_id, "", teams_message],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
            task_queue=QUEUE_INTERACTIONS,
        )
        welcome_email_task = workflow.execute_activity(
            email_send,
            args=[request.tenant_id, request.welcome_email, welcome_subject, welcome_body],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
            task_queue=QUEUE_INTERACTIONS,
        )
        ticket_task = create_soc_ticket(
            request.tenant_id,
            request.config,
            title=f"[ONBOARDING] {request.display_name}",
            description=(
                f"Tenant onboarding completed for {request.tenant_id}.\n"
                f"Customer: {request.display_name}\n"
                f"Analyst: {request.analyst_email}\n"
                f"Created subscriptions: {len(request.created_subscription_ids)}"
            ),
            severity="low",
            source_workflow="WF-CUST-ONBOARDING",
        )

        parallel_results = await asyncio.gather(
            teams_task,
            welcome_email_task,
            ticket_task,
            return_exceptions=True,
        )

        errors = [item for item in parallel_results if isinstance(item, Exception)]
        if errors:
            first_error = errors[0]
            if isinstance(first_error, ApplicationError):
                raise first_error
            raise ApplicationError(
                f"Onboarding communications stage failed: {type(first_error).__name__}",
                type="OnboardingCommunicationsFailed",
                non_retryable=False,
            )

        ticket: TicketResult = parallel_results[2]  # type: ignore[assignment]
        return OnboardingCommunicationsStageResult(ticket=ticket)
