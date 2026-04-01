from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.ticketing import ticket_create
    from shared.models import TicketCreationRequest, TicketData, TicketResult

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class TicketCreationWorkflow:
    """Reusable child workflow for creating a SOC ticket through provider connectors."""

    @workflow.run
    async def run(self, request: TicketCreationRequest) -> TicketResult:
        workflow.logger.info(
            "TicketCreationWorkflow gestart — tenant=%s source=%s",
            request.tenant_id,
            request.source_workflow,
        )

        return await workflow.execute_activity(
            ticket_create,
            args=[
                request.tenant_id,
                request.ticketing_provider,
                TicketData(
                    tenant_id=request.tenant_id,
                    title=request.title,
                    description=request.description,
                    severity=request.severity,
                    source_workflow=request.source_workflow,
                ),
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
