from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.config import QUEUE_EDR
    from shared.models import (
        AlertEnrichmentRequest,
        AlertEnrichmentResult,
        TicketResult,
        TenantConfig,
    )
    from shared.models.canonical import DefenderDetectionFindingEvent, Envelope
    from shared.workflow_helpers import (
        bootstrap_tenant,
        create_soc_ticket,
        emit_workflow_observability,
        resolve_threat_intel,
    )
    from workflows.child.alert_enrichment import AlertEnrichmentWorkflow

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)

@workflow.defn
class DefenderAlertEnrichmentWorkflow:
    """
    WF-02 — Defender Alert Enrichment & Ticketing (SOC automation).
    Task Queue: edr
    """

    @workflow.run
    async def run(self, event: Envelope) -> str:
        if not isinstance(event.payload, DefenderDetectionFindingEvent):
            raise ValueError("WF-02 requires defender.alert payload in Envelope input")

        payload = event.payload
        source_ip = None
        destination_ip = None
        vendor_source = payload.vendor_extensions.get("source_ip")
        if vendor_source is not None and isinstance(vendor_source.value, str):
            source_ip = vendor_source.value
        vendor_destination = payload.vendor_extensions.get("destination_ip")
        if vendor_destination is not None and isinstance(vendor_destination.value, str):
            destination_ip = vendor_destination.value

        workflow.logger.info(
            f"WF-02 gestart — tenant={event.tenant_id}, "
            f"alert={payload.alert_id}, severity={payload.severity}"
        )

        config: TenantConfig = await bootstrap_tenant(
            tenant_id=event.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        ticketing_enabled = config.auto_ticket_creation

        # 4. Threat intelligence lookup
        indicator = source_ip or destination_ip or ""
        threat_intel = await resolve_threat_intel(event.tenant_id, indicator, config)

        # 5. Enrichment + risicoscore via child workflow
        enrich_and_risk: AlertEnrichmentResult = await workflow.execute_child_workflow(
            AlertEnrichmentWorkflow.run,
            AlertEnrichmentRequest(
                tenant_id=event.tenant_id,
                alert=payload,
                edr_provider=config.edr_provider,
                identity_provider=config.iam_provider,
                threat_intel=threat_intel,
            ),
            id=f"{workflow.info().workflow_id}-alert-enrichment",
            task_queue=QUEUE_EDR,
        )
        enriched = enrich_and_risk.enriched_alert
        risk = enrich_and_risk.risk_score

        ticket = TicketResult(ticket_id="NOT-CREATED", status="skipped", url="")
        if ticketing_enabled:
            ticket = await create_soc_ticket(
                event.tenant_id,
                config,
                title=f"[{risk.level.upper()}] {enriched.title}",
                description=(
                    f"Alert: {enriched.alert_id}\n"
                    f"Severity: {enriched.severity}\n"
                    f"Risk score: {risk.score} ({risk.level})\n"
                    f"Factors: {', '.join(risk.factors)}\n\n"
                    f"Beschrijving: {enriched.description}\n"
                    f"Gebruiker: {enriched.user_display_name} ({enriched.user_department})\n"
                    f"Device: {enriched.device_display_name} ({enriched.device_os})\n"
                    f"Threat intel: {threat_intel.details}"
                ),
                severity=risk.level,
                source_workflow="WF-02",
            )

        # 7. Teams notificatie
        notification_msg = (
            f"🚨 Nieuw SOC-ticket {ticket.ticket_id}\n"
            f"Alert: {enriched.title} ({risk.level})\n"
            f"Score: {risk.score}/100\n"
            f"Ticket: {ticket.url}"
        )

        await emit_workflow_observability(
            event.tenant_id,
            workflow_id=workflow.info().workflow_id,
            action="defender_alert_enrichment",
            result=f"Ticket {ticket.ticket_id} aangemaakt met risicoscore {risk.score}",
            metadata={
                "alert_id": enriched.alert_id,
                "risk_score": risk.score,
                "risk_level": risk.level,
                "ticket_id": ticket.ticket_id,
                "requester": str(event.metadata.get("requester") or "ingress-api"),
            },
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
            notification_message=notification_msg,
        )

        result_msg = (
            f"WF-02 afgerond — alert '{enriched.alert_id}' verrijkt, "
            f"risicoscore {risk.score} ({risk.level}), "
            f"ticketstatus: {ticket.status} ({ticket.ticket_id})."
        )
        workflow.logger.info(result_msg)
        return result_msg
