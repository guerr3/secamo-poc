from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey

with workflow.unsafe.imports_passed_through():
    from activities.edr import edr_get_identity_risk, edr_get_signin_history
    from shared.config import QUEUE_EDR, QUEUE_INTERACTIONS
    from shared.models import (
        ApprovalDecision,
        HiTLApprovalRequest,
        HiTLRequest,
        IncidentResponseRequest,
        IdentityRiskContext,
        SecurityCaseInput,
        TenantConfig,
        ThreatIntelResult,
        TicketResult,
    )
    from shared.workflow_helpers import (
        bootstrap_tenant,
        create_soc_ticket,
        emit_workflow_observability,
        resolve_threat_intel,
    )
    from workflows.child.incident_response import IncidentResponseWorkflow
    from workflows.child.hitl_approval import HiTLApprovalWorkflow


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
TENANT_ID_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("TenantId")
CASE_TYPE_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("CaseType")
SEVERITY_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("Severity")


def _risk_level(identity_risk: IdentityRiskContext | None) -> str:
    if identity_risk is None or not identity_risk.risk_level:
        return "none"
    return str(identity_risk.risk_level).strip().lower() or "none"


def _requester(case_input: SecurityCaseInput) -> str:
    if case_input.source_event is None:
        return "ingress-api"
    return str(case_input.source_event.metadata.get("requester") or "ingress-api")


def _signin_has_anomaly_indicators(signin_history: list[dict[str, Any]]) -> bool:
    for record in signin_history:
        risk_level = str(
            record.get("riskLevelDuringSignIn")
            or record.get("riskLevelAggregated")
            or record.get("riskLevel")
            or ""
        ).strip().lower()
        if risk_level in {"medium", "high", "critical"}:
            return True

        risk_state = str(record.get("riskState") or "").strip().lower()
        if risk_state in {"atrisk", "confirmedcompromised"}:
            return True

        status = record.get("status")
        if isinstance(status, dict):
            error_code = status.get("errorCode")
            if isinstance(error_code, int) and error_code != 0:
                return True

        result = str(record.get("result") or record.get("resultType") or "").strip().lower()
        if result in {"failure", "failed", "blocked"}:
            return True

        if bool(record.get("flaggedForReview", False)):
            return True

    return False


@workflow.defn
class SigninAnomalyDetectionWorkflow:
    """Analyze sign-in signal cases and escalate only confirmed anomalies."""

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
                "allowed_actions": ["dismiss", "disable_user"],
            }
        )

        lookup_key = case_input.identity or case_input.alert_id
        identity_risk: IdentityRiskContext | None = await workflow.execute_activity(
            edr_get_identity_risk,
            args=[case_input.tenant_id, lookup_key],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )
        signin_history: list[dict[str, Any]] = await workflow.execute_activity(
            edr_get_signin_history,
            args=[case_input.tenant_id, lookup_key, 20],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        identity_risk_level = _risk_level(identity_risk)
        has_anomaly = _signin_has_anomaly_indicators(signin_history)
        if identity_risk_level in {"none", "low"} and not has_anomaly:
            await emit_workflow_observability(
                case_input.tenant_id,
                workflow_id=workflow.info().workflow_id,
                action="signin_anomaly_detection",
                result="Sign-in signal closed without escalation (low risk and no anomaly indicators).",
                metadata={
                    "case_type": case_input.case_type,
                    "alert_id": case_input.alert_id,
                    "severity": case_input.severity,
                    "identity": case_input.identity,
                    "identity_risk_level": identity_risk_level,
                    "signin_record_count": len(signin_history),
                    "requester": _requester(case_input),
                },
                timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            return "Signin anomaly triage completed without escalation."

        threat_indicator = case_input.identity or case_input.alert_id
        threat_intel: ThreatIntelResult = await resolve_threat_intel(
            case_input.tenant_id,
            threat_indicator,
            config,
        )

        ticket: TicketResult = await create_soc_ticket(
            case_input.tenant_id,
            config,
            title=f"[{case_input.severity.upper()}] Sign-in anomaly for {case_input.identity or 'unknown identity'}",
            description=(
                f"Case type: {case_input.case_type}\n"
                f"Signal id: {case_input.alert_id}\n"
                f"Identity: {case_input.identity or 'unknown'}\n"
                f"Identity risk: {identity_risk_level}\n"
                f"Sign-in records inspected: {len(signin_history)}\n"
                f"Threat intel: {threat_intel.details}"
            ),
            severity=case_input.severity,
            source_workflow="WF-SIGNIN-ANOMALY",
        )

        hitl_request = HiTLRequest(
            workflow_id=workflow.info().workflow_id,
            run_id="",
            tenant_id=case_input.tenant_id,
            title="Sign-in anomaly analyst review",
            description="Review sign-in anomaly evidence and choose a response action.",
            allowed_actions=case_input.allowed_actions,
            reviewer_email=config.soc_analyst_email or (case_input.identity or "soc@secamo.local"),
            ticket_key=ticket.ticket_id,
            channels=["email", "jira"],
            timeout_hours=config.hitl_timeout_hours,
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "identity": case_input.identity,
                "identity_risk_level": identity_risk_level,
                "ticket_id": ticket.ticket_id,
            },
        )

        decision: ApprovalDecision | None = await workflow.execute_child_workflow(
            HiTLApprovalWorkflow.run,
            HiTLApprovalRequest(
                tenant_id=case_input.tenant_id,
                hitl_request=hitl_request,
                hitl_timeout_hours=config.hitl_timeout_hours,
                auto_isolate_on_timeout=config.auto_isolate_on_timeout,
                escalation_enabled=config.escalation_enabled,
                edr_provider=config.edr_provider,
                ticketing_provider=config.ticketing_provider,
                device_id=case_input.device,
            ),
            id=f"{workflow.info().workflow_id}-hitl-approval",
            task_queue=QUEUE_INTERACTIONS,
        )

        remediation_result = "not_triggered"
        if (
            decision is not None
            and decision.approved
            and decision.action in case_input.allowed_actions
        ):
            if workflow.patched("signin-incident-response-v1"):
                remediation_result = await workflow.execute_child_workflow(
                    IncidentResponseWorkflow.run,
                    IncidentResponseRequest(
                        tenant_id=case_input.tenant_id,
                        decision=decision,
                        user=None,
                        user_email=case_input.identity or "unknown@example.com",
                        device_id=case_input.device,
                        ticket_id=ticket.ticket_id,
                        evidence_bundle_enabled=config.evidence_bundle_enabled,
                        edr_provider=config.edr_provider,
                        ticketing_provider=config.ticketing_provider,
                        parent_workflow_id=workflow.info().workflow_id,
                        alert_id=case_input.alert_id,
                        threat_intel=threat_intel,
                        recent_alert_count=len(signin_history),
                    ),
                    id=f"{workflow.info().workflow_id}-incident-response",
                    task_queue=QUEUE_EDR,
                )
            else:
                remediation_result = "legacy_no_incident_response"

        await emit_workflow_observability(
            case_input.tenant_id,
            workflow_id=workflow.info().workflow_id,
            action="signin_anomaly_detection",
            result=(
                "Sign-in anomaly case escalated for analyst decision "
                f"(ticket={ticket.ticket_id}, decision={decision.action if decision else 'timeout_or_none'}, "
                f"remediation={remediation_result})."
            ),
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "severity": case_input.severity,
                "identity": case_input.identity,
                "identity_risk_level": identity_risk_level,
                "ticket_id": ticket.ticket_id,
                "decision": decision.action if decision else "timeout_or_none",
                "remediation_result": remediation_result,
                "requester": _requester(case_input),
            },
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        return (
            "Signin anomaly triage completed "
            f"(ticket={ticket.ticket_id}, decision={decision.action if decision else 'timeout_or_none'}, "
            f"remediation={remediation_result})."
        )
