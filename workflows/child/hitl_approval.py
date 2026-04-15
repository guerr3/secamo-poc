from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey

with workflow.unsafe.imports_passed_through():
    from activities.edr import edr_isolate_device
    from activities.hitl import request_hitl_approval
    from activities.ticketing import ticket_update
    from shared.models import ApprovalDecision, HiTLApprovalRequest, HiTLRequest

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
TENANT_ID_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("TenantId")
HITL_STATUS_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("HiTLStatus")


def _rebind_hitl_request_for_child(
    original_request: HiTLRequest,
    *,
    child_workflow_id: str,
    child_run_id: str,
) -> HiTLRequest:
    """Return an immutable HiTL request bound to the child workflow identity."""
    request_payload = original_request.model_dump(mode="python")
    request_payload["workflow_id"] = child_workflow_id
    request_payload["run_id"] = child_run_id
    return HiTLRequest(**request_payload)


@workflow.defn
class HiTLApprovalWorkflow:
    """Reusable child workflow that owns the HITL signal lifecycle."""

    def __init__(self) -> None:
        self._approval: ApprovalDecision | None = None

    @workflow.signal
    async def approve(self, decision: ApprovalDecision) -> None:
        self._approval = decision

    @workflow.run
    async def run(self, request: HiTLApprovalRequest) -> ApprovalDecision | None:
        if workflow.patched("hitl-search-attributes-v1"):
            workflow.upsert_search_attributes(
                [
                    TENANT_ID_SEARCH_ATTRIBUTE.value_set(request.tenant_id),
                    HITL_STATUS_SEARCH_ATTRIBUTE.value_set("pending"),
                ]
            )

        child_hitl_request = _rebind_hitl_request_for_child(
            request.hitl_request,
            child_workflow_id=workflow.info().workflow_id,
            child_run_id=workflow.info().run_id,
        )

        workflow.logger.info(
            "HiTLApprovalWorkflow gestart — tenant=%s workflow_id=%s",
            request.tenant_id,
            child_hitl_request.workflow_id,
        )

        dispatch_result = await workflow.execute_activity(
            request_hitl_approval,
            args=[
                request.tenant_id,
                child_hitl_request,
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
        workflow.logger.info(
            "HiTLApprovalWorkflow dispatch result workflow_id=%s channels=%s",
            dispatch_result.workflow_id,
            [item.channel for item in dispatch_result.channel_results],
        )

        approval_timeout = timedelta(hours=request.hitl_timeout_hours)
        try:
            await workflow.wait_condition(lambda: self._approval is not None, timeout=approval_timeout)
        except TimeoutError:
            if workflow.patched("hitl-search-attributes-v1"):
                workflow.upsert_search_attributes(
                    [HITL_STATUS_SEARCH_ATTRIBUTE.value_set("timed_out")]
                )

            if request.auto_isolate_on_timeout and request.device_id:
                await workflow.execute_activity(
                    edr_isolate_device,
                    args=[
                        request.tenant_id,
                        request.device_id,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )

            if request.escalation_enabled and child_hitl_request.ticket_key:
                await workflow.execute_activity(
                    ticket_update,
                    args=[
                        request.tenant_id,
                        request.ticketing_provider,
                        child_hitl_request.ticket_key,
                        {
                            "status": "escalated",
                            "note": "Geen beslissing binnen timeout — geescaleerd.",
                        },
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
            return None

        if workflow.patched("hitl-search-attributes-v1"):
            workflow.upsert_search_attributes(
                [HITL_STATUS_SEARCH_ATTRIBUTE.value_set("resolved")]
            )

        return self._approval
