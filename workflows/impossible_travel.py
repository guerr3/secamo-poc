from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.models import (
        ImpossibleTravelRequest,
        TenantSecrets,
        ThreatIntelResult,
        TicketData,
        TicketResult,
        NotificationResult,
        ApprovalDecision,
        EvidenceBundle,
        GraphUser,
    )
    from activities.tenant import validate_tenant_context, get_tenant_secrets
    from activities.graph_users import graph_get_user
    from activities.graph_alerts import (
        graph_get_alerts,
        graph_isolate_device,
        threat_intel_lookup,
    )
    from activities.ticketing import ticket_create, ticket_update
    from activities.notifications import teams_send_adaptive_card
    from activities.audit import collect_evidence_bundle

# ── Module-level constants ────────────────────────────────────
RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
APPROVAL_TIMEOUT = timedelta(hours=4)  # max wachttijd op menselijke beslissing

# Teams webhook URL — TODO: verplaats naar config/tenant secrets
TEAMS_WEBHOOK_URL = "https://outlook.office.com/webhook/stub-webhook-url"


@workflow.defn
class ImpossibleTravelWorkflow:
    """
    WF-05 — Impossible Travel Alert Triage (Advanced HITL).
    Task Queue: soc-defender

    Flow: graph_get_user → threat_intel_lookup → graph_get_alerts →
          ticket_create → teams_send_adaptive_card → wait_for_approval →
          [action based on decision] → collect_evidence_bundle
    """

    def __init__(self) -> None:
        self._approval: ApprovalDecision | None = None

    @workflow.signal
    async def approve(self, decision: ApprovalDecision) -> None:
        """Signal handler — ontvangt de HITL-beslissing van de analist."""
        self._approval = decision

    @workflow.run
    async def run(self, request: ImpossibleTravelRequest) -> str:
        workflow.logger.info(
            f"WF-05 gestart — tenant={request.tenant_id}, "
            f"user={request.user_email}, alert={request.alert.alert_id}"
        )

        # 1. Validate tenant & get secrets
        await workflow.execute_activity(
            validate_tenant_context,
            args=[request.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        secrets: TenantSecrets = await workflow.execute_activity(
            get_tenant_secrets,
            args=[request.tenant_id, "graph"],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 2. Gebruikersgegevens ophalen
        user: GraphUser | None = await workflow.execute_activity(
            graph_get_user,
            args=[request.tenant_id, request.user_email, secrets],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        user_display = user.display_name if user else request.user_email

        # 3. Threat intel lookup op source IP
        threat_intel: ThreatIntelResult = await workflow.execute_activity(
            threat_intel_lookup,
            args=[request.tenant_id, request.source_ip],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 4. Recente alerts ophalen voor deze gebruiker
        recent_alerts: list[dict] = await workflow.execute_activity(
            graph_get_alerts,
            args=[request.tenant_id, request.user_email, secrets],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 5. Ticket aanmaken
        ticket_data = TicketData(
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
            severity="high",
            source_workflow="WF-05",
            related_alert_id=request.alert.alert_id,
        )

        ticket: TicketResult = await workflow.execute_activity(
            ticket_create,
            args=[request.tenant_id, ticket_data],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 6. Adaptive Card sturen naar Teams voor HITL-goedkeuring
        card_payload = {
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                 "text": f"🚨 Impossible Travel — {user_display}"},
                {"type": "FactSet", "facts": [
                    {"title": "Source IP", "value": request.source_ip},
                    {"title": "Destination IP", "value": request.destination_ip},
                    {"title": "Threat Intel", "value":
                        f"{'MALICIOUS' if threat_intel.is_malicious else 'CLEAN'} "
                        f"(score: {threat_intel.reputation_score})"},
                    {"title": "Recente alerts", "value": str(len(recent_alerts))},
                    {"title": "Ticket", "value": ticket.ticket_id},
                ]},
                {"type": "TextBlock", "text": "Kies een actie:", "wrap": True},
            ],
            "actions": [
                {"type": "Action.Submit", "title": "✅ Dismiss (false positive)",
                 "data": {"action": "dismiss"}},
                {"type": "Action.Submit", "title": "🔒 Isolate device",
                 "data": {"action": "isolate"}},
                {"type": "Action.Submit", "title": "🚫 Disable user",
                 "data": {"action": "disable_user"}},
            ],
        }

        await workflow.execute_activity(
            teams_send_adaptive_card,
            args=[request.tenant_id, TEAMS_WEBHOOK_URL, card_payload],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        # 7. Wacht op analist-beslissing (HITL signal)
        workflow.logger.info(
            f"Wacht op analist-goedkeuring (max {APPROVAL_TIMEOUT})..."
        )

        try:
            await workflow.wait_condition(
                lambda: self._approval is not None,
                timeout=APPROVAL_TIMEOUT,
            )
        except TimeoutError:
            # Geen beslissing binnen timeout — escaleer
            await workflow.execute_activity(
                ticket_update,
                args=[
                    request.tenant_id,
                    ticket.ticket_id,
                    {"status": "escalated", "note": "Geen beslissing binnen timeout — geëscaleerd."},
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            return (
                f"WF-05 timeout — geen beslissing ontvangen binnen "
                f"{APPROVAL_TIMEOUT}. Ticket {ticket.ticket_id} geëscaleerd."
            )

        decision = self._approval
        assert decision is not None

        workflow.logger.info(
            f"Beslissing ontvangen: action={decision.action} door {decision.reviewer}"
        )

        # 8. Actie uitvoeren op basis van beslissing
        action_result = ""

        if decision.action == "dismiss":
            await workflow.execute_activity(
                ticket_update,
                args=[
                    request.tenant_id,
                    ticket.ticket_id,
                    {"status": "closed", "resolution": "false_positive",
                     "note": f"Dismissed door {decision.reviewer}: {decision.comments}"},
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            action_result = "Alert dismissed als false positive."

        elif decision.action == "isolate":
            device_id = request.alert.device_id or "unknown-device"
            await workflow.execute_activity(
                graph_isolate_device,
                args=[request.tenant_id, device_id, secrets],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            await workflow.execute_activity(
                ticket_update,
                args=[
                    request.tenant_id,
                    ticket.ticket_id,
                    {"status": "in_progress", "note": f"Device {device_id} geïsoleerd door {decision.reviewer}."},
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            action_result = f"Device '{device_id}' geïsoleerd."

        elif decision.action == "disable_user":
            if user:
                from activities.graph_users import graph_delete_user, graph_revoke_sessions

                await workflow.execute_activity(
                    graph_revoke_sessions,
                    args=[request.tenant_id, user.user_id, secrets],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
                await workflow.execute_activity(
                    graph_delete_user,
                    args=[request.tenant_id, user.user_id, secrets],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=RETRY_POLICY,
                )
            await workflow.execute_activity(
                ticket_update,
                args=[
                    request.tenant_id,
                    ticket.ticket_id,
                    {"status": "in_progress",
                     "note": f"Gebruiker {request.user_email} uitgeschakeld door {decision.reviewer}."},
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            action_result = f"Gebruiker '{request.user_email}' uitgeschakeld."

        # 9. Evidence bundle verzamelen
        evidence: EvidenceBundle = await workflow.execute_activity(
            collect_evidence_bundle,
            args=[
                workflow.info().workflow_id,
                request.tenant_id,
                request.alert.alert_id,
                [
                    {"type": "threat_intel", "data": {
                        "indicator": threat_intel.indicator,
                        "is_malicious": threat_intel.is_malicious,
                        "reputation_score": threat_intel.reputation_score,
                    }},
                    {"type": "recent_alerts", "count": len(recent_alerts)},
                    {"type": "decision", "data": {
                        "action": decision.action,
                        "reviewer": decision.reviewer,
                        "comments": decision.comments,
                    }},
                ],
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        result_msg = (
            f"WF-05 afgerond — {action_result} "
            f"Ticket: {ticket.ticket_id}, Evidence: {evidence.bundle_url}"
        )
        workflow.logger.info(result_msg)
        return result_msg
