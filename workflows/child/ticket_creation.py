from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.connector_dispatch import connector_execute_action
    from shared.models import ConnectorActionResult, TicketCreationRequest, TicketResult

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

        result: ConnectorActionResult = await workflow.execute_activity(
            connector_execute_action,
            args=[
                request.tenant_id,
                request.ticketing_provider,
                "create_ticket",
                {
                    "title": request.title,
                    "description": request.description,
                    "issue_type": "Incident",
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        ticket_key = str(result.data.payload.get("key") or result.data.payload.get("ticket_id") or "UNKNOWN")
        ticket_url = str(result.data.payload.get("url") or "")
        return TicketResult(
            ticket_id=ticket_key,
            status="open",
            url=ticket_url,
        )
