from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.models import (
        DefenderAlertRequest,
        TenantConfig,
        TenantSecrets,
        EnrichedAlert,
        ThreatIntelResult,
        RiskScore,
        ConnectorActionResult,
        TicketResult,
    )
    from shared.workflow_helpers import bootstrap_tenant
    from activities.tenant import get_tenant_secrets
    from activities.risk import calculate_risk_score
    from activities.connector_dispatch import connector_execute_action, connector_threat_intel_fanout
    from activities.notify_teams import teams_send_notification
    from activities.audit import create_audit_log

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

        # 3. Enrich alert via provider connector
        enrich_result: ConnectorActionResult = await workflow.execute_activity(
            connector_execute_action,
            args=[
                request.tenant_id,
                config.edr_provider,
                "enrich_alert",
                {"alert_id": request.alert.alert_id},
                graph_secrets,
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        enriched_payload = enrich_result.data
        enriched = EnrichedAlert(
            alert_id=enriched_payload.get("id", request.alert.alert_id),
            severity=(enriched_payload.get("severity") or request.alert.severity).lower(),
            title=enriched_payload.get("title", request.alert.title),
            description=enriched_payload.get("description", request.alert.description),
            user_display_name=((enriched_payload.get("userStates") or [{}])[0].get("userPrincipalName") if enriched_payload.get("userStates") else request.alert.user_email),
            device_display_name=((enriched_payload.get("deviceEvidence") or [{}])[0].get("deviceDnsName") if enriched_payload.get("deviceEvidence") else request.alert.device_id),
        )

        # 4. Threat intelligence lookup
        indicator = request.alert.source_ip or request.alert.destination_ip or ""
        if config.threat_intel_enabled and ti_secrets:
            threat_intel: ThreatIntelResult = await workflow.execute_activity(
                connector_threat_intel_fanout,
                args=[request.tenant_id, config.threat_intel_providers, indicator, ti_secrets],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
        else:
            threat_intel = ThreatIntelResult(
                indicator=indicator,
                is_malicious=False,
                provider="disabled",
                reputation_score=0.0,
                details="Threat intel disabled by tenant config.",
            )

        # 5. Risicoscore berekenen
        risk: RiskScore = await workflow.execute_activity(
            calculate_risk_score,
            args=[request.tenant_id, enriched, threat_intel],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        ticket = TicketResult(ticket_id="NOT-CREATED", status="skipped", url="")
        if config.auto_ticket_creation and ticketing_secrets:
            ticket_result: ConnectorActionResult = await workflow.execute_activity(
                connector_execute_action,
                args=[
                    request.tenant_id,
                    config.ticketing_provider,
                    "create_ticket",
                    {
                        "project_key": ticketing_secrets.project_key or "SOC",
                        "title": f"[{risk.level.upper()}] {enriched.title}",
                        "description": (
                            f"Alert: {enriched.alert_id}\n"
                            f"Severity: {enriched.severity}\n"
                            f"Risk score: {risk.score} ({risk.level})\n"
                            f"Factors: {', '.join(risk.factors)}\n\n"
                            f"Beschrijving: {enriched.description}\n"
                            f"Gebruiker: {enriched.user_display_name} ({enriched.user_department})\n"
                            f"Device: {enriched.device_display_name} ({enriched.device_os})\n"
                            f"Threat intel: {threat_intel.details}"
                        ),
                        "issue_type": "Incident",
                    },
                    ticketing_secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )

            ticket_key = ticket_result.data.get("key", "UNKNOWN")
            ticket = TicketResult(
                ticket_id=ticket_key,
                status="open",
                url=f"{ticketing_secrets.jira_base_url}/browse/{ticket_key}" if ticketing_secrets.jira_base_url else "",
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
