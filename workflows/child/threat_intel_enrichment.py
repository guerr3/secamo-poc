from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.connector_dispatch import connector_threat_intel_fanout
    from shared.models import ThreatIntelEnrichmentRequest, ThreatIntelResult

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class ThreatIntelEnrichmentWorkflow:
    """Reusable child workflow for threat-intel fanout enrichment."""

    @workflow.run
    async def run(self, request: ThreatIntelEnrichmentRequest) -> ThreatIntelResult:
        workflow.logger.info(
            "ThreatIntelEnrichmentWorkflow gestart — tenant=%s indicator=%s",
            request.tenant_id,
            request.indicator,
        )

        return await workflow.execute_activity(
            connector_threat_intel_fanout,
            args=[
                request.tenant_id,
                request.providers,
                request.indicator,
                request.ti_secrets,
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
