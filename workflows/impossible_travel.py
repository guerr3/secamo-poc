from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.models import (
        ApprovalDecision,
        IdentityUser,
        HiTLApprovalRequest,
        HiTLRequest,
        IncidentResponseRequest,
        TenantConfig,
        TicketResult,
    )
    from shared.models.canonical import Envelope, ImpossibleTravelEvent
    from shared.workflow_helpers import bootstrap_tenant, create_soc_ticket, resolve_threat_intel
    from activities.edr import edr_get_user_alerts
    from activities.identity import identity_get_user
    from workflows.child.hitl_approval import HiTLApprovalWorkflow
    from workflows.child.incident_response import IncidentResponseWorkflow

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)

@workflow.defn
class ImpossibleTravelWorkflow:
    """
    WF-05 — Impossible Travel Alert Triage (Advanced HITL).
    Task Queue: soc-defender

    Flow: identity_get_user → threat_intel_lookup → provider_get_alerts →
          ticket_create → teams_send_adaptive_card → wait_for_approval →
          [action based on decision] → collect_evidence_bundle
    """

    @workflow.run
    async def run(self, event: Envelope) -> str:
        if not isinstance(event.payload, ImpossibleTravelEvent):
            raise ValueError("WF-05 requires defender.impossible_travel payload in Envelope input")

        payload = event.payload
        source_ip = payload.source_ip
        destination_ip = payload.destination_ip

        workflow.logger.info(
            f"WF-05 gestart — tenant={event.tenant_id}, "
            f"user={payload.user_principal_name}, alert={event.event_id}"
        )

        config: TenantConfig = await bootstrap_tenant(
            tenant_id=event.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        # 2. Gebruikersgegevens ophalen
        user: IdentityUser | None = await workflow.execute_activity(
            identity_get_user,
            args=[event.tenant_id, payload.user_principal_name],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        user_display = user.display_name if user else payload.user_principal_name

        threat_intel = await resolve_threat_intel(
            event.tenant_id,
            source_ip or "",
            config,
        )

        # 4. Recente alerts ophalen via provider connector
        recent_alerts: list[dict] = await workflow.execute_activity(
            edr_get_user_alerts,
            args=[event.tenant_id, payload.user_principal_name],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        # 5. Ticket aanmaken via child workflow
        ticket: TicketResult = await create_soc_ticket(
            event.tenant_id,
            config,
            title=f"[IMPOSSIBLE TRAVEL] {user_display}",
            description=(
                f"Impossible travel gedetecteerd voor {user_display}\n"
                f"Source IP: {source_ip or 'unknown'}\n"
                f"Destination IP: {destination_ip or 'unknown'}\n"
                f"Threat intel: {'MALICIOUS' if threat_intel.is_malicious else 'CLEAN'} "
                f"(score: {threat_intel.reputation_score})\n"
                f"Recente alerts: {len(recent_alerts)}\n\n"
                f"Wacht op analist-beslissing..."
            ),
            severity=(payload.severity or "high"),
            source_workflow="WF-05",
        )
        ticket_key = ticket.ticket_id

        hitl_request = HiTLRequest(
            workflow_id=workflow.info().workflow_id,
            run_id="",
            tenant_id=event.tenant_id,
            title=f"Impossible Travel approval required for {user_display}",
            description=(
                f"Impossible travel was detected for {user_display}. "
                f"Review the context and select one response action."
            ),
            allowed_actions=["dismiss", "isolate", "disable_user"],
            reviewer_email=config.soc_analyst_email or payload.user_principal_name,
            ticket_key=ticket_key,
            channels=["email", "jira"],
            timeout_hours=config.hitl_timeout_hours,
            metadata={
                "alert_id": event.event_id,
                "severity": payload.severity,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
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
                tenant_id=event.tenant_id,
                hitl_request=hitl_request,
                hitl_timeout_hours=config.hitl_timeout_hours,
                auto_isolate_on_timeout=config.auto_isolate_on_timeout,
                escalation_enabled=config.escalation_enabled,
                edr_provider=config.edr_provider,
                ticketing_provider=config.ticketing_provider,
                device_id=None,
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
                tenant_id=event.tenant_id,
                decision=decision,
                user=user,
                user_email=payload.user_principal_name,
                device_id=None,
                ticket_id=ticket.ticket_id,
                evidence_bundle_enabled=config.evidence_bundle_enabled,
                edr_provider=config.edr_provider,
                ticketing_provider=config.ticketing_provider,
                parent_workflow_id=workflow.info().workflow_id,
                alert_id=event.event_id,
                threat_intel=threat_intel,
                recent_alert_count=len(recent_alerts),
            ),
            id=f"{workflow.info().workflow_id}-incident-response",
            task_queue="soc-defender",
        )

        result_msg = f"WF-05 afgerond — {action_result}"
        workflow.logger.info(result_msg)
        return result_msg
