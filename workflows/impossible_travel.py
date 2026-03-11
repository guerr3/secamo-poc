from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from shared.models import (
        ImpossibleTravelRequest,
        TenantConfig,
        TenantSecrets,
        ThreatIntelResult,
        ConnectorActionResult,
        TicketResult,
        ApprovalDecision,
        EvidenceBundle,
        GraphUser,
    )
    from shared.workflow_helpers import bootstrap_tenant
    from activities.tenant import get_tenant_secrets
    from activities.graph_users import graph_get_user, graph_delete_user, graph_revoke_sessions
    from activities.connector_dispatch import connector_execute_action, connector_threat_intel_fanout
    from activities.notifications import teams_send_adaptive_card
    from activities.audit import collect_evidence_bundle

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

        config: TenantConfig
        graph_secrets: TenantSecrets
        config, graph_secrets = await bootstrap_tenant(
            tenant_id=request.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
            secret_type="graph",
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)
        approval_timeout = timedelta(hours=config.hitl_timeout_hours)

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
            threat_intel: ThreatIntelResult = await workflow.execute_activity(
                connector_threat_intel_fanout,
                args=[request.tenant_id, config.threat_intel_providers, request.source_ip, ti_secrets],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
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

        # 5. Ticket aanmaken via provider connector
        create_ticket_result: ConnectorActionResult = await workflow.execute_activity(
            connector_execute_action,
            args=[
                request.tenant_id,
                config.ticketing_provider,
                "create_ticket",
                {
                    "project_key": ticketing_secrets.project_key or "SOC",
                    "title": f"[IMPOSSIBLE TRAVEL] {user_display}",
                    "description": (
                        f"Impossible travel gedetecteerd voor {user_display}\n"
                        f"Source IP: {request.source_ip}\n"
                        f"Destination IP: {request.destination_ip}\n"
                        f"Threat intel: {'MALICIOUS' if threat_intel.is_malicious else 'CLEAN'} "
                        f"(score: {threat_intel.reputation_score})\n"
                        f"Recente alerts: {len(recent_alerts)}\n\n"
                        f"Wacht op analist-beslissing..."
                    ),
                    "issue_type": "Incident",
                },
                ticketing_secrets,
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        ticket_key = create_ticket_result.data.get("key", "UNKNOWN")
        ticket = TicketResult(
            ticket_id=ticket_key,
            status="open",
            url=f"{ticketing_secrets.jira_base_url}/browse/{ticket_key}" if ticketing_secrets.jira_base_url else "",
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
            args=[request.tenant_id, graph_secrets.teams_webhook_url or "", card_payload],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        # 7. Wacht op analist-beslissing (HITL signal)
        workflow.logger.info(
            f"Wacht op analist-goedkeuring (max {approval_timeout})..."
        )

        try:
            await workflow.wait_condition(
                lambda: self._approval is not None,
                timeout=approval_timeout,
            )
        except TimeoutError:
            if config.auto_isolate_on_timeout and request.alert.device_id:
                await workflow.execute_activity(
                    connector_execute_action,
                    args=[
                        request.tenant_id,
                        config.edr_provider,
                        "isolate_device",
                        {
                            "device_id": request.alert.device_id,
                            "comment": "Automatic isolation after HITL timeout",
                        },
                        graph_secrets,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )

            if config.escalation_enabled:
                await workflow.execute_activity(
                    connector_execute_action,
                    args=[
                        request.tenant_id,
                        config.ticketing_provider,
                        "update_ticket",
                        {
                            "ticket_id": ticket.ticket_id,
                            "fields": {"status": "escalated", "note": "Geen beslissing binnen timeout — geescaleerd."},
                        },
                        ticketing_secrets,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
            return (
                f"WF-05 timeout — geen beslissing ontvangen binnen "
                f"{approval_timeout}. Ticket {ticket.ticket_id} behandeld volgens tenant policy."
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
                connector_execute_action,
                args=[
                    request.tenant_id,
                    config.ticketing_provider,
                    "update_ticket",
                    {
                        "ticket_id": ticket.ticket_id,
                        "fields": {
                            "status": "closed",
                            "resolution": "false_positive",
                            "note": f"Dismissed door {decision.reviewer}: {decision.comments}",
                        },
                    },
                    ticketing_secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            action_result = "Alert dismissed als false positive."

        elif decision.action == "isolate":
            device_id = request.alert.device_id or "unknown-device"
            await workflow.execute_activity(
                connector_execute_action,
                args=[
                    request.tenant_id,
                    config.edr_provider,
                    "isolate_device",
                    {
                        "device_id": device_id,
                        "comment": f"Isolated by {decision.reviewer} from WF-05",
                    },
                    graph_secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            await workflow.execute_activity(
                connector_execute_action,
                args=[
                    request.tenant_id,
                    config.ticketing_provider,
                    "update_ticket",
                    {
                        "ticket_id": ticket.ticket_id,
                        "fields": {"status": "in_progress", "note": f"Device {device_id} geisoleerd door {decision.reviewer}."},
                    },
                    ticketing_secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            action_result = f"Device '{device_id}' geïsoleerd."

        elif decision.action == "disable_user":
            if user:
                await workflow.execute_activity(
                    graph_revoke_sessions,
                    args=[request.tenant_id, user.user_id, graph_secrets],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                await workflow.execute_activity(
                    graph_delete_user,
                    args=[request.tenant_id, user.user_id, graph_secrets],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
            await workflow.execute_activity(
                connector_execute_action,
                args=[
                    request.tenant_id,
                    config.ticketing_provider,
                    "update_ticket",
                    {
                        "ticket_id": ticket.ticket_id,
                        "fields": {
                            "status": "in_progress",
                            "note": f"Gebruiker {request.user_email} uitgeschakeld door {decision.reviewer}.",
                        },
                    },
                    ticketing_secrets,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            action_result = f"Gebruiker '{request.user_email}' uitgeschakeld."

        evidence_url = "disabled-by-config"
        if config.evidence_bundle_enabled:
            evidence: EvidenceBundle = await workflow.execute_activity(
                collect_evidence_bundle,
                args=[
                    request.tenant_id,
                    workflow.info().workflow_id,
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
                retry_policy=runtime_retry,
            )
            evidence_url = evidence.bundle_url

        result_msg = (
            f"WF-05 afgerond — {action_result} "
            f"Ticket: {ticket.ticket_id}, Evidence: {evidence_url}"
        )
        workflow.logger.info(result_msg)
        return result_msg
