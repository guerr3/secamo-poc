from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.models import (
        ApprovalDecision,
        ConnectorActionResult,
        GraphUser,
        HiTLApprovalRequest,
        HiTLRequest,
        IncidentResponseRequest,
        ImpossibleTravelRequest,
        TenantConfig,
        TenantSecrets,
        ThreatIntelEnrichmentRequest,
        ThreatIntelResult,
        TicketCreationRequest,
        TicketResult,
    )
    from shared.workflow_helpers import bootstrap_tenant
    from activities.tenant import get_tenant_secrets
    from activities.graph_users import graph_get_user
    from activities.connector_dispatch import connector_execute_action
    from workflows.child.hitl_approval import HiTLApprovalWorkflow
    from workflows.child.incident_response import IncidentResponseWorkflow
    from workflows.child.threat_intel_enrichment import ThreatIntelEnrichmentWorkflow
    from workflows.child.ticket_creation import TicketCreationWorkflow

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)

@workflow.defn
class ImpossibleTravelWorkflow:
    """
    WF-05 — Impossible Travel Alert Triage (Advanced HITL).
    Task Queue: soc-defender

    Flow: graph_get_user → threat_intel_lookup → graph_get_alerts →
          ticket_create → teams_send_adaptive_card → wait_for_approval →
          [action based on decision] → collect_evidence_bundle
    """

    @workflow.run
    async def run(self, request: ImpossibleTravelRequest) -> str:
        workflow.logger.info(
            f"WF-05 gestart — tenant={request.tenant_id}, "
            f"user={request.user_email}, alert={request.alert.alert_id}"
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

        ticketing_secrets: TenantSecrets = await workflow.execute_activity(
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

        # 2. Gebruikersgegevens ophalen
        user: GraphUser | None = await workflow.execute_activity(
            graph_get_user,
            args=[request.tenant_id, request.user_email, graph_secrets],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        user_display = user.display_name if user else request.user_email

        # 3. Threat intel lookup op source IP
        if config.threat_intel_enabled and ti_secrets:
            threat_intel = await workflow.execute_child_workflow(
                ThreatIntelEnrichmentWorkflow.run,
                ThreatIntelEnrichmentRequest(
                    tenant_id=request.tenant_id,
                    indicator=request.source_ip,
                    providers=config.threat_intel_providers,
                    ti_secrets=ti_secrets,
                ),
                id=f"{workflow.info().workflow_id}-ti",
                task_queue="soc-defender",
            )
        else:
            threat_intel = ThreatIntelResult(
                indicator=request.source_ip,
                is_malicious=False,
                provider="disabled",
                reputation_score=0.0,
                details="Threat intel disabled by tenant config.",
            )

        # 4. Recente alerts ophalen via provider connector
        alerts_result: ConnectorActionResult = await workflow.execute_activity(
            connector_execute_action,
            args=[
                request.tenant_id,
                config.edr_provider,
                "get_user_alerts",
                {"user_email": request.user_email},
                graph_secrets,
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )
        recent_alerts: list[dict] = alerts_result.data.get("alerts", [])

        # 5. Ticket aanmaken via child workflow
        ticket: TicketResult = await workflow.execute_child_workflow(
            TicketCreationWorkflow.run,
            TicketCreationRequest(
                tenant_id=request.tenant_id,
                title=f"[IMPOSSIBLE TRAVEL] {user_display}",
                description=(
                    f"Impossible travel gedetecteerd voor {user_display}\n"
                    f"Source IP: {request.source_ip}\n"
                    f"Destination IP: {request.destination_ip}\n"
                    f"Threat intel: {'MALICIOUS' if threat_intel.is_malicious else 'CLEAN'} "
                    f"(score: {threat_intel.reputation_score})\n"
                    f"Recente alerts: {len(recent_alerts)}\n\n"
                    f"Wacht op analist-beslissing..."
                ),
                severity=request.alert.severity,
                source_workflow="WF-05",
                ticketing_provider=config.ticketing_provider,
                ticketing_secrets=ticketing_secrets,
            ),
            id=f"{workflow.info().workflow_id}-ticket",
            task_queue="soc-defender",
        )
        ticket_key = ticket.ticket_id

        hitl_request = HiTLRequest(
            workflow_id=workflow.info().workflow_id,
            tenant_id=request.tenant_id,
            title=f"Impossible Travel approval required for {user_display}",
            description=(
                f"Impossible travel was detected for {user_display}. "
                f"Review the context and select one response action."
            ),
            allowed_actions=["dismiss", "isolate", "disable_user"],
            reviewer_email=config.soc_analyst_email or request.user_email,
            ticket_key=ticket_key,
            channels=["email", "jira"],
            timeout_hours=config.hitl_timeout_hours,
            metadata={
                "alert_id": request.alert.alert_id,
                "severity": request.alert.severity,
                "source_ip": request.source_ip,
                "destination_ip": request.destination_ip,
                "risk_indicator": "malicious" if threat_intel.is_malicious else "clean",
                "risk_score": threat_intel.reputation_score,
                "recent_alert_count": len(recent_alerts),
                "ticket_id": ticket.ticket_id,
            },
        )

        # 6. HITL approval flow (signal + timeout policy) via child workflow
        decision: ApprovalDecision | None = await workflow.execute_child_workflow(
            HiTLApprovalWorkflow.run,
            HiTLApprovalRequest(
                tenant_id=request.tenant_id,
                hitl_request=hitl_request,
                config=config,
                graph_secrets=graph_secrets,
                ticketing_secrets=ticketing_secrets,
                edr_provider=config.edr_provider,
                ticketing_provider=config.ticketing_provider,
                device_id=request.alert.device_id,
            ),
            id=f"{workflow.info().workflow_id}-hitl",
            task_queue="soc-defender",
        )

        if decision is None:
            return (
                f"WF-05 timeout — geen beslissing ontvangen binnen "
                f"{timedelta(hours=config.hitl_timeout_hours)}. "
                f"Ticket {ticket.ticket_id} behandeld volgens tenant policy."
            )

        # 7. Post-decision incident response via child workflow
        action_result = await workflow.execute_child_workflow(
            IncidentResponseWorkflow.run,
            IncidentResponseRequest(
                tenant_id=request.tenant_id,
                decision=decision,
                user=user,
                user_email=request.user_email,
                device_id=request.alert.device_id,
                ticket_id=ticket.ticket_id,
                config=config,
                graph_secrets=graph_secrets,
                ticketing_secrets=ticketing_secrets,
                edr_provider=config.edr_provider,
                ticketing_provider=config.ticketing_provider,
                parent_workflow_id=workflow.info().workflow_id,
                alert_id=request.alert.alert_id,
                threat_intel=threat_intel,
                recent_alert_count=len(recent_alerts),
            ),
            id=f"{workflow.info().workflow_id}-incident-response",
            task_queue="soc-defender",
        )

        result_msg = f"WF-05 afgerond — {action_result}"
        workflow.logger.info(result_msg)
        return result_msg
