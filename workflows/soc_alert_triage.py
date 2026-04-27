from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey

with workflow.unsafe.imports_passed_through():
    from shared.config import QUEUE_EDR, QUEUE_TICKETING
    from shared.models import (
        AlertEnrichmentRequest,
        AlertEnrichmentWorkflowResult,
        ApprovalDecision,
        HiTLRequest,
        IncidentResponseRequest,
        SecurityCaseInput,
        TenantConfig,
        TicketCreationRequest,
        TicketResult,
        ThreatIntelEnrichmentRequest,
        ThreatIntelResult,
    )
    from shared.workflow_helpers import (
        bootstrap_tenant,
        emit_workflow_observability,
        persist_case_record,
        request_hitl_decision,
        update_case,
    )
    from workflows.child.alert_enrichment import AlertEnrichmentWorkflow
    from workflows.child.incident_response import IncidentResponseWorkflow
    from workflows.child.threat_intel_enrichment import ThreatIntelEnrichmentWorkflow
    from workflows.child.ticket_creation import TicketCreationWorkflow


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
TENANT_ID_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("TenantId")
CASE_TYPE_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("CaseType")
SEVERITY_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("Severity")


def _source_vendor_string(case_input: SecurityCaseInput, key: str) -> str | None:
    source_event = case_input.source_event
    if source_event is None:
        return None

    vendor_extensions = getattr(source_event.payload, "vendor_extensions", None)
    if not isinstance(vendor_extensions, dict):
        return None

    extension = vendor_extensions.get(key)
    if extension is None:
        return None

    value = getattr(extension, "value", None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _requester(case_input: SecurityCaseInput) -> str:
    if case_input.source_event is None:
        return "ingress-api"
    return str(case_input.source_event.metadata.get("requester") or "ingress-api")


def _resolve_threat_indicator(case_input: SecurityCaseInput) -> str:
    source_ip = _source_vendor_string(case_input, "source_ip")
    if source_ip:
        return source_ip

    source_event = case_input.source_event
    if source_event is not None:
        payload_source_ip = getattr(source_event.payload, "source_ip", None)
        if isinstance(payload_source_ip, str) and payload_source_ip.strip():
            return payload_source_ip.strip()

    return case_input.alert_id


@workflow.defn
class SocAlertTriageWorkflow:
    """Unified SOC alert triage workflow for defender alerts, impossible travel, and security signals."""

    def __init__(self) -> None:
        self._approval: ApprovalDecision | None = None

    def _clear_approval(self) -> None:
        self._approval = None

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
        case_input = case_input.model_copy(update={"auto_remediate": bool(config.auto_isolate_on_timeout)})

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

        workflow.logger.info(
            "SocAlertTriageWorkflow started tenant=%s case_type=%s alert_id=%s",
            case_input.tenant_id,
            case_input.case_type,
            case_input.alert_id,
        )

        if case_input.case_type == "generic_signal":
            await emit_workflow_observability(
                case_input.tenant_id,
                workflow_id=workflow.info().workflow_id,
                action="case_intake",
                result=(
                    "Generic security signal ingested for audit/log only path "
                    f"(alert_id={case_input.alert_id})."
                ),
                metadata={
                    "case_type": case_input.case_type,
                    "alert_id": case_input.alert_id,
                    "severity": case_input.severity,
                    "requester": _requester(case_input),
                },
                timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )

            await update_case(
                case_input.tenant_id,
                case_id,
                "closed",
                timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )

            return "Case intake complete (generic signal audit path)."

        indicator = _resolve_threat_indicator(case_input)
        child_prefix = f"{workflow.info().workflow_id}-{case_input.case_type}"

        threat_intel: ThreatIntelResult = await workflow.execute_child_workflow(
            ThreatIntelEnrichmentWorkflow.run,
            ThreatIntelEnrichmentRequest(
                tenant_id=case_input.tenant_id,
                indicator=indicator,
                providers=config.threat_intel_providers,
            ),
            id=f"{child_prefix}-threat-intel",
            task_queue=QUEUE_EDR,
            execution_timeout=timedelta(minutes=5),
        )

        enrichment_result: AlertEnrichmentWorkflowResult = await workflow.execute_child_workflow(
            AlertEnrichmentWorkflow.run,
            AlertEnrichmentRequest(
                tenant_id=case_input.tenant_id,
                case_input=case_input,
                threat_indicator=indicator,
                edr_provider=config.edr_provider,
                identity_provider=config.iam_provider,
                threat_intel=threat_intel,
            ),
            id=f"{child_prefix}-alert-enrichment",
            task_queue=QUEUE_EDR,
            execution_timeout=timedelta(minutes=5),
        )

        risk = enrichment_result.risk_score
        enriched = enrichment_result.enriched_alert

        ticket: TicketResult = await workflow.execute_child_workflow(
            TicketCreationWorkflow.run,
            TicketCreationRequest(
                tenant_id=case_input.tenant_id,
                title=f"[{risk.level.upper()}] {enriched.title}",
                description=(
                    f"Case type: {case_input.case_type}\n"
                    f"Alert: {enriched.alert_id}\n"
                    f"Severity: {enriched.severity}\n"
                    f"Risk score: {risk.score} ({risk.level})\n"
                    f"Threat intel: {threat_intel.details}"
                ),
                severity=risk.level,
                source_workflow="WF-CASE-INTAKE",
                ticketing_provider=config.ticketing_provider,
            ),
            id=f"{child_prefix}-ticket-creation",
            task_queue=QUEUE_TICKETING,
            execution_timeout=timedelta(minutes=5),
        )

        await update_case(
            case_input.tenant_id,
            case_id,
            "open",
            ticket_id=ticket.ticket_id,
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        hitl_request = HiTLRequest(
            workflow_id=workflow.info().workflow_id,
            run_id="",
            tenant_id=case_input.tenant_id,
            title=f"Security case approval required ({case_input.case_type})",
            description=(
                "Review the enriched security case and choose one response action. "
                f"Risk level: {risk.level}."
            ),
            allowed_actions=case_input.allowed_actions,
            reviewer_email=config.soc_analyst_email or (case_input.identity or "soc@secamo.local"),
            ticket_key=ticket.ticket_id,
            channels=["email", "jira"],
            timeout_hours=config.hitl_timeout_hours,
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "severity": case_input.severity,
                "risk_level": risk.level,
                "risk_score": risk.score,
                "indicator": indicator,
                "ticket_id": ticket.ticket_id,
            },
        )

        decision = await request_hitl_decision(
            case_input.tenant_id,
            hitl_request,
            approval_getter=lambda: self._approval,
            clear_approval=self._clear_approval,
            config=config,
            ticket_id=ticket.ticket_id,
            device_id=case_input.device,
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        remediation_result = "remediation skipped"
        if (
            decision
            and decision.approved
            and case_input.auto_remediate
            and decision.action in case_input.allowed_actions
        ):
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
                    recent_alert_count=0,
                ),
                id=f"{child_prefix}-incident-response",
                task_queue=QUEUE_EDR,
                execution_timeout=timedelta(minutes=5),
            )

        final_status = "auto_remediated" if decision is None and config.auto_isolate_on_timeout and case_input.device else (
            "dismissed" if decision and decision.action == "dismiss" else "closed"
        )
        await update_case(
            case_input.tenant_id,
            case_id,
            final_status,
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        await emit_workflow_observability(
            case_input.tenant_id,
            workflow_id=workflow.info().workflow_id,
            action="case_intake",
            result=(
                f"Case processed case_type={case_input.case_type} ticket={ticket.ticket_id} "
                f"risk={risk.level} remediation={remediation_result}"
            ),
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "ticket_id": ticket.ticket_id,
                "risk_level": risk.level,
                "risk_score": risk.score,
                "decision": decision.action if decision else "timeout_or_none",
                "requester": _requester(case_input),
            },
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
            notification_message=(
                f"Case intake completed for {case_input.case_type}. "
                f"Ticket {ticket.ticket_id}, risk={risk.level}."
            ),
        )

        return (
            f"Case intake completed for {case_input.case_type} "
            f"(ticket={ticket.ticket_id}, remediation={remediation_result})."
        )
