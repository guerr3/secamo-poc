from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.models import (
        DefenderAlertRequest,
        TenantSecrets,
        EnrichedAlert,
        ThreatIntelResult,
        RiskScore,
        TicketData,
        TicketResult,
        NotificationResult,
    )
    from activities.tenant import validate_tenant_context, get_tenant_secrets
    from activities.graph_alerts import (
        graph_enrich_alert,
        threat_intel_lookup,
        calculate_risk_score,
    )
    from activities.ticketing import ticket_create
    from activities.notifications import teams_send_notification
    from activities.audit import create_audit_log

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)

# Teams webhook URL — TODO: verplaats naar config/tenant secrets
TEAMS_WEBHOOK_URL = "https://outlook.office.com/webhook/stub-webhook-url"


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

        # 1. Validate tenant
        await workflow.execute_activity(
            validate_tenant_context,
            args=[request.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 2. Get tenant secrets
        secrets: TenantSecrets = await workflow.execute_activity(
            get_tenant_secrets,
            args=[request.tenant_id, "graph"],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 3. Enrich alert met Graph API context
        enriched: EnrichedAlert = await workflow.execute_activity(
            graph_enrich_alert,
            args=[request.tenant_id, request.alert, secrets],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 4. Threat intelligence lookup
        indicator = request.alert.source_ip or request.alert.destination_ip or ""
        threat_intel: ThreatIntelResult = await workflow.execute_activity(
            threat_intel_lookup,
            args=[request.tenant_id, indicator],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 5. Risicoscore berekenen
        risk: RiskScore = await workflow.execute_activity(
            calculate_risk_score,
            args=[request.tenant_id, enriched, threat_intel],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 6. Ticket aanmaken
        ticket_data = TicketData(
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
            related_alert_id=enriched.alert_id,
        )

        ticket: TicketResult = await workflow.execute_activity(
            ticket_create,
            args=[request.tenant_id, ticket_data],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
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
            args=[request.tenant_id, TEAMS_WEBHOOK_URL, notification_msg],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 8. Audit log
        await workflow.execute_activity(
            create_audit_log,
            args=[
                workflow.info().workflow_id,
                request.tenant_id,
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
            retry_policy=RETRY_POLICY,
        )

        result_msg = (
            f"WF-02 afgerond — alert '{enriched.alert_id}' verrijkt, "
            f"risicoscore {risk.score} ({risk.level}), "
            f"ticket {ticket.ticket_id} aangemaakt."
        )
        workflow.logger.info(result_msg)
        return result_msg
