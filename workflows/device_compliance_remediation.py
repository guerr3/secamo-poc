from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey

with workflow.unsafe.imports_passed_through():
    from activities.edr import (
        edr_enrich_alert,
        edr_get_device_context,
        edr_isolate_device,
        edr_run_antivirus_scan,
    )
    from shared.config import QUEUE_INTERACTIONS
    from shared.models import (
        ApprovalDecision,
        ConnectorActionResult,
        DeviceContext,
        HiTLApprovalRequest,
        HiTLRequest,
        SecurityCaseInput,
        TenantConfig,
        TicketResult,
    )
    from shared.workflow_helpers import bootstrap_tenant, create_soc_ticket, emit_workflow_observability
    from workflows.child.hitl_approval import HiTLApprovalWorkflow


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
TENANT_ID_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("TenantId")
CASE_TYPE_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("CaseType")
SEVERITY_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("Severity")


def _requester(case_input: SecurityCaseInput) -> str:
    if case_input.source_event is None:
        return "ingress-api"
    return str(case_input.source_event.metadata.get("requester") or "ingress-api")


def _is_low_device_risk(device_context: DeviceContext | None) -> bool:
    if device_context is None or not device_context.risk_score:
        return False

    raw_risk = str(device_context.risk_score).strip().lower()
    if raw_risk in {"none", "low", "minimal"}:
        return True

    try:
        return float(raw_risk) <= 30.0
    except ValueError:
        return False


@workflow.defn
class DeviceComplianceRemediationWorkflow:
    """Handle noncompliant-device signal cases and orchestrate analyst-guided response."""

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
                "allowed_actions": ["isolate_device", "run_antivirus_scan", "dismiss"],
            }
        )

        device_id = case_input.device
        if not device_id:
            await emit_workflow_observability(
                case_input.tenant_id,
                workflow_id=workflow.info().workflow_id,
                action="device_compliance_remediation",
                result="Case closed without action because device identifier is missing.",
                metadata={
                    "case_type": case_input.case_type,
                    "alert_id": case_input.alert_id,
                    "severity": case_input.severity,
                    "requester": _requester(case_input),
                },
                timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            return "Device compliance remediation skipped due to missing device identifier."

        device_context: DeviceContext | None = await workflow.execute_activity(
            edr_get_device_context,
            args=[case_input.tenant_id, device_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )
        alert_context: dict[str, Any] = await workflow.execute_activity(
            edr_enrich_alert,
            args=[case_input.tenant_id, case_input.alert_id, None],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        if _is_low_device_risk(device_context) and case_input.severity == "low":
            await emit_workflow_observability(
                case_input.tenant_id,
                workflow_id=workflow.info().workflow_id,
                action="device_compliance_remediation",
                result="Low-severity noncompliant device case closed without escalation.",
                metadata={
                    "case_type": case_input.case_type,
                    "alert_id": case_input.alert_id,
                    "severity": case_input.severity,
                    "device": device_id,
                    "device_risk_score": device_context.risk_score if device_context else None,
                    "requester": _requester(case_input),
                },
                timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )
            return "Device compliance remediation completed without escalation."

        ticket: TicketResult = await create_soc_ticket(
            case_input.tenant_id,
            config,
            title=f"[{case_input.severity.upper()}] Noncompliant device triage for {device_id}",
            description=(
                f"Case type: {case_input.case_type}\n"
                f"Signal id: {case_input.alert_id}\n"
                f"Device: {device_id}\n"
                f"Device compliance: {device_context.compliance_state if device_context else 'unknown'}\n"
                f"Device risk score: {device_context.risk_score if device_context else 'unknown'}\n"
                f"Alert context title: {alert_context.get('title') or 'n/a'}"
            ),
            severity=case_input.severity,
            source_workflow="WF-DEVICE-COMPLIANCE-REMEDIATION",
        )

        hitl_request = HiTLRequest(
            workflow_id=workflow.info().workflow_id,
            run_id="",
            tenant_id=case_input.tenant_id,
            title="Device compliance remediation approval",
            description="Choose the response action for this noncompliant device case.",
            allowed_actions=case_input.allowed_actions,
            reviewer_email=config.soc_analyst_email or "soc@secamo.local",
            ticket_key=ticket.ticket_id,
            channels=["email", "jira"],
            timeout_hours=config.hitl_timeout_hours,
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "device": device_id,
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
                device_id=device_id,
            ),
            id=f"{workflow.info().workflow_id}-hitl-approval",
            task_queue=QUEUE_INTERACTIONS,
        )

        action_taken = "timeout_or_none"
        if decision is not None:
            if decision.action == "isolate_device":
                await workflow.execute_activity(
                    edr_isolate_device,
                    args=[case_input.tenant_id, device_id],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                action_taken = "isolate_device"
            elif decision.action == "run_antivirus_scan":
                scan_result: ConnectorActionResult = await workflow.execute_activity(
                    edr_run_antivirus_scan,
                    args=[case_input.tenant_id, device_id, "Quick"],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                action_taken = f"run_antivirus_scan:{'success' if scan_result.success else 'submitted_with_issue'}"
            elif decision.action == "dismiss":
                action_taken = "dismiss"
            else:
                action_taken = f"unsupported:{decision.action}"

        await emit_workflow_observability(
            case_input.tenant_id,
            workflow_id=workflow.info().workflow_id,
            action="device_compliance_remediation",
            result=(
                "Device compliance case processed "
                f"(ticket={ticket.ticket_id}, action={action_taken})."
            ),
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "severity": case_input.severity,
                "device": device_id,
                "device_risk_score": device_context.risk_score if device_context else None,
                "ticket_id": ticket.ticket_id,
                "decision": decision.action if decision else "timeout_or_none",
                "requester": _requester(case_input),
            },
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        return f"Device compliance remediation completed (ticket={ticket.ticket_id}, action={action_taken})."
