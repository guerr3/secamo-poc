from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError


with workflow.unsafe.imports_passed_through():
    from shared.config import QUEUE_EDR, QUEUE_USER_LIFECYCLE
    from shared.models import (
        OnboardingBootstrapStageRequest,
        OnboardingBootstrapStageResult,
        OnboardingCommunicationsStageRequest,
        OnboardingCommunicationsStageResult,
        OnboardingComplianceEvidenceStageRequest,
        OnboardingComplianceEvidenceStageResult,
        OnboardingSubscriptionReconcileStageRequest,
        OnboardingSubscriptionReconcileStageResult,
    )
    from shared.models.canonical import CustomerOnboardingEvent, Envelope
    from workflows.child.onboarding_bootstrap_stage import OnboardingBootstrapStageWorkflow
    from workflows.child.onboarding_communications_stage import OnboardingCommunicationsStageWorkflow
    from workflows.child.onboarding_compliance_evidence_stage import OnboardingComplianceEvidenceStageWorkflow
    from workflows.child.onboarding_subscription_reconcile_stage import OnboardingSubscriptionReconcileStageWorkflow


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class CustomerOnboardingWorkflow:
    """Tenant onboarding command workflow composed from reusable onboarding stages."""

    @workflow.run
    async def run(self, event: Envelope) -> str:
        if not isinstance(event.payload, CustomerOnboardingEvent):
            raise ValueError("CustomerOnboardingWorkflow requires customer.onboarding payload")

        payload = event.payload
        if payload.tenant_id != event.tenant_id:
            raise ApplicationError(
                "Envelope tenant_id and payload tenant_id must match",
                type="TenantMismatch",
                non_retryable=True,
            )

        workflow.logger.info("WF-CUST-ONBOARDING started tenant=%s", event.tenant_id)
        requester = str(event.metadata.get("requester") or "onboarding-api")

        bootstrap_result: OnboardingBootstrapStageResult = await workflow.execute_child_workflow(
            OnboardingBootstrapStageWorkflow.run,
            OnboardingBootstrapStageRequest(
                tenant_id=event.tenant_id,
                payload=payload,
                requester=requester,
            ),
            id=f"{workflow.info().workflow_id}-bootstrap",
            task_queue=QUEUE_USER_LIFECYCLE,
        )

        reconcile_result: OnboardingSubscriptionReconcileStageResult = await workflow.execute_child_workflow(
            OnboardingSubscriptionReconcileStageWorkflow.run,
            OnboardingSubscriptionReconcileStageRequest(
                tenant_id=event.tenant_id,
                config=bootstrap_result.config,
                partial_onboarding=bootstrap_result.partial_onboarding,
                notification_url=bootstrap_result.notification_url,
            ),
            id=f"{workflow.info().workflow_id}-subscriptions",
            task_queue=QUEUE_EDR,
        )

        communication_result: OnboardingCommunicationsStageResult = await workflow.execute_child_workflow(
            OnboardingCommunicationsStageWorkflow.run,
            OnboardingCommunicationsStageRequest(
                tenant_id=event.tenant_id,
                config=bootstrap_result.config,
                display_name=bootstrap_result.display_name,
                analyst_email=bootstrap_result.analyst_email,
                welcome_email=bootstrap_result.welcome_email,
                created_subscription_ids=reconcile_result.created_subscription_ids,
                active_subscription_count=reconcile_result.active_subscription_count,
            ),
            id=f"{workflow.info().workflow_id}-communications",
            task_queue=QUEUE_USER_LIFECYCLE,
        )

        _compliance_result: OnboardingComplianceEvidenceStageResult = await workflow.execute_child_workflow(
            OnboardingComplianceEvidenceStageWorkflow.run,
            OnboardingComplianceEvidenceStageRequest(
                tenant_id=event.tenant_id,
                workflow_id=workflow.info().workflow_id,
                event_id=event.event_id,
                requester=bootstrap_result.requester,
                display_name=bootstrap_result.display_name,
                created_subscription_ids=reconcile_result.created_subscription_ids,
            ),
            id=f"{workflow.info().workflow_id}-compliance",
            task_queue=QUEUE_USER_LIFECYCLE,
        )

        result_msg = (
            f"Customer onboarding completed for tenant '{event.tenant_id}' "
            f"with ticket {communication_result.ticket.ticket_id} "
            f"and {len(reconcile_result.created_subscription_ids)} new subscriptions."
        )
        workflow.logger.info(result_msg)
        return result_msg
