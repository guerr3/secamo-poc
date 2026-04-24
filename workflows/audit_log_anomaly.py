from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey

with workflow.unsafe.imports_passed_through():
    from activities.edr import edr_isolate_device
    from activities.hitl import request_hitl_approval
    from activities.identity import identity_get_identity_risk, identity_get_user
    from activities.ticketing import ticket_update
    from shared.models import (
        ApprovalDecision,
        HiTLRequest,
        IdentityRiskContext,
        IdentityUser,
        SecurityCaseInput,
        TenantConfig,
        TicketResult,
    )
    from shared.workflow_helpers import (
        bootstrap_tenant,
        create_soc_ticket,
        emit_workflow_observability,
        persist_case_record,
        update_case,
    )


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
TENANT_ID_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("TenantId")
CASE_TYPE_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("CaseType")
SEVERITY_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("Severity")


def _requester(case_input: SecurityCaseInput) -> str:
    if case_input.source_event is None:
        return "ingress-api"
    return str(case_input.source_event.metadata.get("requester") or "ingress-api")


def _risk_level(identity_risk: IdentityRiskContext | None) -> str:
    if identity_risk is None or not identity_risk.risk_level:
        return "none"
    return str(identity_risk.risk_level).strip().lower() or "none"


@workflow.defn
class AuditLogAnomalyWorkflow:
    """Monitor audit-log anomaly signals and escalate suspicious operations."""

    def __init__(self) -> None:
        self._approval: ApprovalDecision | None = None

    @workflow.signal
    async def approve(self, decision: ApprovalDecision) -> None:
        self._approval = decision

    @workflow.run
    async def run(self, case_input: SecurityCaseInput) -> str:
        workflow.upsert_search_attributes(
            [
                TENANT_ID_SEARCH_ATTRIBUTE.value_set(case_input.tenant_id),
                CASE_TYPE_SEARCH_ATTRIBUTE.value_set(case_input.case_type),
                SEVERITY_SEARCH_ATTRIBUTE.value_set(case_input.severity),
            ]
        )

        config: TenantConfig = await bootstrap_tenant(
            tenant_id=case_input.tenant_id,
            retry_policy=RETRY_POLICY,
            timeout=TIMEOUT,
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)
        case_input = case_input.model_copy(
            update={
                "auto_remediate": bool(config.auto_isolate_on_timeout),
                "allowed_actions": ["dismiss"],
            }
        )

        case_id = str(workflow.uuid4())
        await persist_case_record(
            case_input.tenant_id,
            case_id,
            workflow.info().workflow_id,
            case_input.case_type,
            case_input.severity,
            source_event_id=case_input.alert_id,
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        identity_lookup = case_input.identity or case_input.alert_id
        identity_user: IdentityUser | None = await workflow.execute_activity(
            identity_get_user,
            args=[case_input.tenant_id, identity_lookup],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        risk_lookup = identity_user.user_id if identity_user else identity_lookup
        identity_risk: IdentityRiskContext | None = await workflow.execute_activity(
            identity_get_identity_risk,
            args=[case_input.tenant_id, risk_lookup],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        risk_level = _risk_level(identity_risk)
        priority = (
            "P1"
            if case_input.severity in {"critical", "high"} or risk_level in {"high", "critical"}
            else "P2"
        )

        # Gate: suppress SOC ticket for P2/low-risk anomalies — no
        # infrastructure cost for benign signals.
        if priority == "P2" and risk_level in {"none", "low"}:
            await emit_workflow_observability(
                case_input.tenant_id,
                workflow_id=workflow.info().workflow_id,
                action="audit_log_anomaly",
                result=(
                    "Audit log anomaly closed without ticket "
                    f"(priority={priority}, risk={risk_level})."
                ),
                metadata={
                    "case_type": case_input.case_type,
                    "alert_id": case_input.alert_id,
                    "severity": case_input.severity,
                    "priority": priority,
                    "identity": case_input.identity,
                    "identity_risk_level": risk_level,
                    "requester": _requester(case_input),
                },
                timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            return "Audit log anomaly completed without escalation (suppressed)."

        ticket: TicketResult = await create_soc_ticket(
            case_input.tenant_id,
            config,
            title=f"[{priority}] Audit log anomaly for {case_input.identity or 'unknown identity'}",
            description=(
                f"Case type: {case_input.case_type}\n"
                f"Signal id: {case_input.alert_id}\n"
                f"Identity: {case_input.identity or 'unknown'}\n"
                f"Risk level: {risk_level}\n"
                f"Priority: {priority}"
            ),
            severity=priority,
            source_workflow="WF-AUDIT-LOG-ANOMALY",
        )

        await update_case(
            case_input.tenant_id, case_id, "open",
            ticket_id=ticket.ticket_id,
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        hitl_request = HiTLRequest(
            workflow_id=workflow.info().workflow_id,
            run_id="",
            tenant_id=case_input.tenant_id,
            title="Audit log anomaly review",
            description="Review audit anomaly context and close with analyst decision.",
            allowed_actions=case_input.allowed_actions,
            reviewer_email=config.soc_analyst_email or (case_input.identity or "soc@secamo.local"),
            ticket_key=ticket.ticket_id,
            channels=["email", "jira"],
            timeout_hours=config.hitl_timeout_hours,
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "priority": priority,
                "risk_level": risk_level,
                "ticket_id": ticket.ticket_id,
            },
        )

        decision: ApprovalDecision | None
        self._approval = None
        hitl_request = hitl_request.model_copy(
            update={
                "run_id": workflow.info().run_id,
            }
        )
        await workflow.execute_activity(
            request_hitl_approval,
            args=[case_input.tenant_id, hitl_request],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )
        try:
            await workflow.wait_condition(
                lambda: self._approval is not None,
                timeout=timedelta(hours=config.hitl_timeout_hours),
            )
            decision = self._approval
        except TimeoutError:
            if config.auto_isolate_on_timeout and case_input.device:
                await workflow.execute_activity(
                    edr_isolate_device,
                    args=[
                        case_input.tenant_id,
                        case_input.device,
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )

            if config.escalation_enabled and ticket.ticket_id:
                await workflow.execute_activity(
                    ticket_update,
                    args=[
                        case_input.tenant_id,
                        config.ticketing_provider,
                        ticket.ticket_id,
                        {
                            "status": "escalated",
                            "note": "Geen beslissing binnen timeout — geescaleerd.",
                        },
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
            decision = None

        final_status = "dismissed" if decision and decision.action == "dismiss" else "closed"
        await update_case(
            case_input.tenant_id, case_id, final_status,
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        await emit_workflow_observability(
            case_input.tenant_id,
            workflow_id=workflow.info().workflow_id,
            action="audit_log_anomaly",
            result=(
                "Audit log anomaly processed "
                f"(ticket={ticket.ticket_id}, priority={priority}, decision={decision.action if decision else 'timeout_or_none'})."
            ),
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "severity": case_input.severity,
                "priority": priority,
                "identity": case_input.identity,
                "identity_risk_level": risk_level,
                "ticket_id": ticket.ticket_id,
                "decision": decision.action if decision else "timeout_or_none",
                "requester": _requester(case_input),
            },
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        return (
            "Audit log anomaly workflow completed "
            f"(ticket={ticket.ticket_id}, decision={decision.action if decision else 'timeout_or_none'})."
        )
