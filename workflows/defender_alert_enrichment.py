from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.models import (
        AlertEnrichmentRequest,
        AlertEnrichmentResult,
        DefenderAlertRequest,
        TicketResult,
        TenantConfig,
        TenantSecrets,
        ThreatIntelEnrichmentRequest,
        ThreatIntelResult,
        TicketCreationRequest,
    )
    from shared.workflow_helpers import bootstrap_tenant
    from activities.tenant import get_tenant_secrets
    from activities.notify_teams import teams_send_notification
    from activities.audit import create_audit_log
    from workflows.child.alert_enrichment import AlertEnrichmentWorkflow
    from workflows.child.threat_intel_enrichment import ThreatIntelEnrichmentWorkflow
    from workflows.child.ticket_creation import TicketCreationWorkflow

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)

@workflow.defn
class DefenderAlertEnrichmentWorkflow:
    """
    WF-02 — Defender Alert Enrichment & Ticketing (SOC automation).
    Task Queue: soc-defender
    """

    @workflow.run
    async def run(self, request: DefenderAlertRequest) -> str:
        workflow.logger.info(
            f"WF-02 gestart — tenant={request.tenant_id}, "
            f"alert={request.alert.alert_id}, severity={request.alert.severity}"
        )

        config: TenantConfig
        graph_secrets: TenantSecrets
        config, graph_secrets = await bootstrap_tenant(
            tenant_id=request.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
            secret_type="graph",
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        ticketing_secrets: TenantSecrets | None = None
        if config.auto_ticket_creation:
            ticketing_secrets = await workflow.execute_activity(
                get_tenant_secrets,
                args=[request.tenant_id, "ticketing"],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )

        ti_secrets: TenantSecrets | None = None
        if config.threat_intel_enabled:
            ti_secrets = await workflow.execute_activity(
                get_tenant_secrets,
                args=[request.tenant_id, "threatintel"],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )

        # 4. Threat intelligence lookup
        indicator = request.alert.source_ip or request.alert.destination_ip or ""
        if config.threat_intel_enabled and ti_secrets:
            threat_intel = await workflow.execute_child_workflow(
                ThreatIntelEnrichmentWorkflow.run,
                ThreatIntelEnrichmentRequest(
                    tenant_id=request.tenant_id,
                    indicator=indicator,
                    providers=config.threat_intel_providers,
                    ti_secrets=ti_secrets,
                ),
                id=f"{workflow.info().workflow_id}-ti",
                task_queue="soc-defender",
            )
        else:
            threat_intel = ThreatIntelResult(
                indicator=indicator,
                is_malicious=False,
                provider="disabled",
                reputation_score=0.0,
                details="Threat intel disabled by tenant config.",
            )

        # 5. Enrichment + risicoscore via child workflow
        enrich_and_risk: AlertEnrichmentResult = await workflow.execute_child_workflow(
            AlertEnrichmentWorkflow.run,
            AlertEnrichmentRequest(
                tenant_id=request.tenant_id,
                alert=request.alert,
                edr_provider=config.edr_provider,
                graph_secrets=graph_secrets,
                threat_intel=threat_intel,
            ),
            id=f"{workflow.info().workflow_id}-alert-enrichment",
            task_queue="soc-defender",
        )
        enriched = enrich_and_risk.enriched_alert
        risk = enrich_and_risk.risk_score

        ticket = TicketResult(ticket_id="NOT-CREATED", status="skipped", url="")
        if config.auto_ticket_creation and ticketing_secrets:
            ticket = await workflow.execute_child_workflow(
                TicketCreationWorkflow.run,
                TicketCreationRequest(
                    tenant_id=request.tenant_id,
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
                    ticketing_provider=config.ticketing_provider,
                    ticketing_secrets=ticketing_secrets,
                ),
                id=f"{workflow.info().workflow_id}-ticket",
                task_queue="soc-defender",
            )

        # 7. Teams notificatie
        notification_msg = (
            f"🚨 Nieuw SOC-ticket {ticket.ticket_id}\n"
            f"Alert: {enriched.title} ({risk.level})\n"
            f"Score: {risk.score}/100\n"
            f"Ticket: {ticket.url}"
        )

        await workflow.execute_activity(
            teams_send_notification,
            args=[request.tenant_id, graph_secrets.teams_webhook_url or "", notification_msg],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        # 8. Audit log
        await workflow.execute_activity(
            create_audit_log,
            args=[
                request.tenant_id,
                workflow.info().workflow_id,
                "defender_alert_enrichment",
                f"Ticket {ticket.ticket_id} aangemaakt met risicoscore {risk.score}",
                {
                    "alert_id": enriched.alert_id,
                    "risk_score": risk.score,
                    "risk_level": risk.level,
                    "ticket_id": ticket.ticket_id,
                    "requester": request.requester,
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        result_msg = (
            f"WF-02 afgerond — alert '{enriched.alert_id}' verrijkt, "
            f"risicoscore {risk.score} ({risk.level}), "
            f"ticketstatus: {ticket.status} ({ticket.ticket_id})."
        )
        workflow.logger.info(result_msg)
        return result_msg
