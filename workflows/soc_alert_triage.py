from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributeKey

with workflow.unsafe.imports_passed_through():
    from shared.config import QUEUE_EDR, QUEUE_INTERACTIONS, QUEUE_TICKETING
    from shared.models import (
        AlertEnrichmentRequest,
        AlertEnrichmentResult,
        ApprovalDecision,
        HiTLApprovalRequest,
        HiTLRequest,
        IncidentResponseRequest,
        SecurityCaseInput,
        TenantConfig,
        TicketCreationRequest,
        TicketResult,
        ThreatIntelEnrichmentRequest,
        ThreatIntelResult,
    )
    from shared.models.canonical import (
        DefenderDetectionFindingEvent,
        DefenderSecuritySignalEvent,
        Envelope,
        ImpossibleTravelEvent,
        VendorExtension,
    )
    from shared.normalization import (
        normalize_defender_alert_case,
        normalize_impossible_travel_case,
    )
    from shared.workflow_helpers import bootstrap_tenant, emit_workflow_observability
    from workflows.child.alert_enrichment import AlertEnrichmentWorkflow
    from workflows.child.hitl_approval import HiTLApprovalWorkflow
    from workflows.child.incident_response import IncidentResponseWorkflow
    from workflows.child.threat_intel_enrichment import ThreatIntelEnrichmentWorkflow
    from workflows.child.ticket_creation import TicketCreationWorkflow


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
TENANT_ID_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("TenantId")
CASE_TYPE_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("CaseType")
SEVERITY_SEARCH_ATTRIBUTE = SearchAttributeKey.for_keyword("Severity")


def _safe_severity(value: str | None, default: str) -> str:
    normalized = str(value or default).strip().lower() or default
    return normalized if normalized in {"low", "medium", "high", "critical"} else default


def _vendor_string(payload: object, key: str) -> str | None:
    vendor_extensions = getattr(payload, "vendor_extensions", None)
    if not isinstance(vendor_extensions, dict):
        return None

    extension = vendor_extensions.get(key)
    if extension is None:
        return None

    value = getattr(extension, "value", None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _to_security_case_input(event: Envelope) -> SecurityCaseInput:
    payload = event.payload

    if isinstance(payload, DefenderDetectionFindingEvent):
        return normalize_defender_alert_case(event, auto_remediate=False)

    if isinstance(payload, ImpossibleTravelEvent):
        return normalize_impossible_travel_case(event, auto_remediate=False)

    if isinstance(payload, DefenderSecuritySignalEvent):
        case_type = (
            "risky_user"
            if "riskyuser" in payload.resource_type.replace("_", "").lower()
            else "generic_signal"
        )
        return SecurityCaseInput(
            tenant_id=event.tenant_id,
            case_type=case_type,
            severity=_safe_severity(payload.severity, "medium"),
            alert_id=payload.signal_id,
            allowed_actions=["dismiss", "isolate", "disable_user"],
            auto_remediate=False,
            identity=_vendor_string(payload, "user_email"),
            device=_vendor_string(payload, "device_id"),
            source_event=event,
        )

    raise ValueError(
        "SocAlertTriageWorkflow requires defender.alert, impossible_travel, or security_signal payload"
    )


def _build_alert_payload(case_input: SecurityCaseInput) -> DefenderDetectionFindingEvent:
    source_event = case_input.source_event
    if source_event is None:
        raise ValueError("SecurityCaseInput.source_event is required for enrichment chain")

    payload = source_event.payload
    if isinstance(payload, DefenderDetectionFindingEvent):
        return payload

    if isinstance(payload, ImpossibleTravelEvent):
        vendor_extensions = dict(payload.vendor_extensions)
        if payload.source_ip:
            vendor_extensions["source_ip"] = VendorExtension(source="impossible_travel", value=payload.source_ip)
        if payload.destination_ip:
            vendor_extensions["destination_ip"] = VendorExtension(source="impossible_travel", value=payload.destination_ip)
        if payload.user_principal_name:
            vendor_extensions["user_email"] = VendorExtension(
                source="impossible_travel",
                value=payload.user_principal_name,
            )
        if case_input.device:
            vendor_extensions["device_id"] = VendorExtension(source="impossible_travel", value=case_input.device)

        return DefenderDetectionFindingEvent(
            event_type="defender.alert",
            activity_id=2004,
            activity_name="impossible_travel_promoted",
            alert_id=case_input.alert_id,
            title=f"Impossible travel detection for {payload.user_principal_name}",
            description=payload.message or "Impossible travel detection converted to SOC alert case.",
            severity_id=payload.severity_id,
            severity=case_input.severity,
            status="open",
            vendor_extensions=vendor_extensions,
        )

    if isinstance(payload, DefenderSecuritySignalEvent):
        vendor_extensions = dict(payload.vendor_extensions)
        return DefenderDetectionFindingEvent(
            event_type="defender.alert",
            activity_id=2004,
            activity_name="security_signal_promoted",
            alert_id=case_input.alert_id,
            title=payload.title,
            description=payload.description,
            severity_id=payload.severity_id,
            severity=case_input.severity,
            status=payload.status,
            vendor_extensions=vendor_extensions,
        )

    raise ValueError("Unsupported source event for alert enrichment mapping")


def _resolve_threat_indicator(case_input: SecurityCaseInput) -> str:
    source_event = case_input.source_event
    if source_event is None:
        return case_input.alert_id

    payload = source_event.payload
    source_ip = _vendor_string(payload, "source_ip")
    if source_ip:
        return source_ip

    if isinstance(payload, ImpossibleTravelEvent) and payload.source_ip:
        return payload.source_ip

    return case_input.alert_id


@workflow.defn
class SocAlertTriageWorkflow:
    """Unified SOC alert triage workflow for defender alerts, impossible travel, and security signals."""

    @workflow.run
    async def run(self, event: Envelope) -> str:
        workflow.patched("soc-alert-triage-rename-v1")
        case_input = _to_security_case_input(event)

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
                    "requester": str(event.metadata.get("requester") or "ingress-api"),
                },
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

        alert_payload = _build_alert_payload(case_input)
        enrichment_result: AlertEnrichmentResult = await workflow.execute_child_workflow(
            AlertEnrichmentWorkflow.run,
            AlertEnrichmentRequest(
                tenant_id=case_input.tenant_id,
                alert=alert_payload,
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
            id=f"{child_prefix}-hitl-approval",
            task_queue=QUEUE_INTERACTIONS,
            execution_timeout=timedelta(minutes=5),
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
                "requester": str(event.metadata.get("requester") or "ingress-api"),
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
