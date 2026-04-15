from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.audit import create_audit_log
    from shared.models import (
        OnboardingComplianceEvidenceStageRequest,
        OnboardingComplianceEvidenceStageResult,
    )


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class OnboardingComplianceEvidenceStageWorkflow:
    """Record onboarding completion evidence for compliance/audit."""

    @workflow.run
    async def run(
        self,
        request: OnboardingComplianceEvidenceStageRequest,
    ) -> OnboardingComplianceEvidenceStageResult:
        written = await workflow.execute_activity(
            create_audit_log,
            args=[
                request.tenant_id,
                request.workflow_id,
                "customer_onboarding",
                f"Customer onboarding completed for {request.display_name}",
                {
                    "event_id": request.event_id,
                    "requester": request.requester,
                    "created_subscription_ids": request.created_subscription_ids,
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        return OnboardingComplianceEvidenceStageResult(audit_written=bool(written))
