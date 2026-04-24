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
    from activities.hitl import request_hitl_approval
    from activities.ticketing import ticket_update
    from shared.models import (
        ApprovalDecision,
        ConnectorActionResult,
        DeviceContext,
        HiTLRequest,
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
                "allowed_actions": ["isolate_device", "run_antivirus_scan", "dismiss"],
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
            if config.auto_isolate_on_timeout and device_id:
                await workflow.execute_activity(
                    edr_isolate_device,
                    args=[
                        case_input.tenant_id,
                        device_id,
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

        final_status = "auto_remediated" if decision is None and config.auto_isolate_on_timeout else (
            "dismissed" if decision and decision.action == "dismiss" else
            "closed" if decision else "closed"
        )
        await update_case(
            case_input.tenant_id, case_id, final_status,
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
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
