from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey

with workflow.unsafe.imports_passed_through():
    from activities.edr import (
        edr_confirm_user_compromised,
        edr_dismiss_risky_user,
        edr_get_identity_risk,
        edr_get_signin_history,
    )
    from activities.identity import identity_generate_temp_password, identity_reset_password, identity_revoke_sessions
    from activities.ticketing import ticket_update
    from shared.config import QUEUE_INTERACTIONS
    from shared.models import (
        ApprovalDecision,
        HiTLApprovalRequest,
        HiTLRequest,
        IdentityRiskContext,
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


def _risk_level(identity_risk: IdentityRiskContext | None) -> str:
    if identity_risk is None or not identity_risk.risk_level:
        return "none"
    return str(identity_risk.risk_level).strip().lower() or "none"


def _source_entity_id(case_input: SecurityCaseInput) -> str | None:
    if case_input.source_event is None:
        return None
    extension = case_input.source_event.payload.vendor_extensions.get("entity_id")
    if extension is None:
        return None
    if isinstance(extension.value, str) and extension.value.strip():
        return extension.value.strip()
    return None


@workflow.defn
class RiskyUserTriageWorkflow:
    """Triage risky-user signal cases with analyst approval and guided response."""

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
                "allowed_actions": ["confirm_compromised", "reset_password", "dismiss"],
            }
        )

        user_lookup = _source_entity_id(case_input) or case_input.identity or case_input.alert_id
        identity_risk: IdentityRiskContext | None = await workflow.execute_activity(
            edr_get_identity_risk,
            args=[case_input.tenant_id, user_lookup],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )
        signin_history: list[dict[str, Any]] = await workflow.execute_activity(
            edr_get_signin_history,
            args=[case_input.tenant_id, case_input.identity or user_lookup, 20],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        ticket: TicketResult = await create_soc_ticket(
            case_input.tenant_id,
            config,
            title=f"[{case_input.severity.upper()}] Risky user triage for {case_input.identity or user_lookup}",
            description=(
                f"Case type: {case_input.case_type}\n"
                f"Signal id: {case_input.alert_id}\n"
                f"Identity: {case_input.identity or 'unknown'}\n"
                f"User lookup key: {user_lookup}\n"
                f"Risk level: {_risk_level(identity_risk)}\n"
                f"Sign-in records inspected: {len(signin_history)}"
            ),
            severity=case_input.severity,
            source_workflow="WF-RISKY-USER-TRIAGE",
        )

        hitl_request = HiTLRequest(
            workflow_id=workflow.info().workflow_id,
            run_id="",
            tenant_id=case_input.tenant_id,
            title="Risky user triage approval",
            description="Select the remediation action for this risky user case.",
            allowed_actions=case_input.allowed_actions,
            reviewer_email=config.soc_analyst_email or (case_input.identity or "soc@secamo.local"),
            ticket_key=ticket.ticket_id,
            channels=["email", "jira"],
            timeout_hours=config.hitl_timeout_hours,
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "identity": case_input.identity,
                "user_lookup": user_lookup,
                "risk_level": _risk_level(identity_risk),
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

        action_taken = "timeout_or_none"
        if decision is not None:
            if decision.action == "confirm_compromised":
                await workflow.execute_activity(
                    edr_confirm_user_compromised,
                    args=[case_input.tenant_id, user_lookup],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                action_taken = "confirm_compromised"
            elif decision.action == "reset_password":
                temp_password = await workflow.execute_activity(
                    identity_generate_temp_password,
                    args=[16],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                await workflow.execute_activity(
                    identity_reset_password,
                    args=[case_input.tenant_id, user_lookup, temp_password],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                await workflow.execute_activity(
                    identity_revoke_sessions,
                    args=[case_input.tenant_id, user_lookup],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                action_taken = "reset_password"
            elif decision.action == "dismiss":
                await workflow.execute_activity(
                    edr_dismiss_risky_user,
                    args=[case_input.tenant_id, user_lookup],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                action_taken = "dismiss"
            else:
                action_taken = f"unsupported:{decision.action}"

        await workflow.execute_activity(
            ticket_update,
            args=[
                case_input.tenant_id,
                config.ticketing_provider,
                ticket.ticket_id,
                {
                    "status": "closed",
                    "resolution": "handled",
                    "note": (
                        f"Risky user triage completed with action '{action_taken}'. "
                        f"Reviewer={decision.reviewer if decision else 'n/a'}"
                    ),
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        await emit_workflow_observability(
            case_input.tenant_id,
            workflow_id=workflow.info().workflow_id,
            action="risky_user_triage",
            result=(
                "Risky user triage completed "
                f"(ticket={ticket.ticket_id}, action={action_taken})."
            ),
            metadata={
                "case_type": case_input.case_type,
                "alert_id": case_input.alert_id,
                "severity": case_input.severity,
                "identity": case_input.identity,
                "user_lookup": user_lookup,
                "risk_level": _risk_level(identity_risk),
                "ticket_id": ticket.ticket_id,
                "decision": decision.action if decision else "timeout_or_none",
                "requester": _requester(case_input),
            },
            timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        return f"Risky user triage completed (ticket={ticket.ticket_id}, action={action_taken})."
