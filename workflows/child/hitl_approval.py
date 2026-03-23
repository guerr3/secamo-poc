from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.connector_dispatch import connector_execute_action
    from activities.hitl import request_hitl_approval
    from activities.notify_teams import teams_send_notification
    from shared.models import ApprovalDecision, HiTLApprovalRequest

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


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
        workflow.logger.info(
            "HiTLApprovalWorkflow gestart — tenant=%s workflow_id=%s",
            request.tenant_id,
            request.hitl_request.workflow_id,
        )

        await workflow.execute_activity(
            request_hitl_approval,
            args=[
                request.tenant_id,
                request.hitl_request,
                request.graph_secrets,
                request.ticketing_secrets,
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        try:
            await workflow.execute_activity(
                teams_send_notification,
                args=[
                    request.tenant_id,
                    request.graph_secrets.teams_webhook_url or "",
                    (
                        f"HITL decision requested. Ticket: {request.hitl_request.ticket_key}. "
                        f"Awaiting signal on child workflow {workflow.info().workflow_id}."
                    ),
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
        except Exception as exc:
            workflow.logger.warning("HITL Teams reminder failed; continuing: %s", exc)

        approval_timeout = timedelta(hours=request.config.hitl_timeout_hours)
        try:
            await workflow.wait_condition(lambda: self._approval is not None, timeout=approval_timeout)
        except TimeoutError:
            if request.config.auto_isolate_on_timeout and request.device_id:
                await workflow.execute_activity(
                    connector_execute_action,
                    args=[
                        request.tenant_id,
                        request.edr_provider,
                        "isolate_device",
                        {
                            "device_id": request.device_id,
                            "comment": "Automatic isolation after HITL timeout",
                        },
                        request.graph_secrets,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )

            if request.config.escalation_enabled and request.hitl_request.ticket_key:
                await workflow.execute_activity(
                    connector_execute_action,
                    args=[
                        request.tenant_id,
                        request.ticketing_provider,
                        "update_ticket",
                        {
                            "ticket_id": request.hitl_request.ticket_key,
                            "fields": {
                                "status": "escalated",
                                "note": "Geen beslissing binnen timeout — geescaleerd.",
                            },
                        },
                        request.ticketing_secrets,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
            return None

        return self._approval
