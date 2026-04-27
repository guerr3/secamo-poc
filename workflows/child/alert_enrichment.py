from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.edr import edr_enrich_alert, edr_get_device_context
    from activities.identity import identity_get_identity_risk
    from activities.risk import calculate_risk_score
    from shared.models import (
        AlertEnrichmentResult,
        AlertEnrichmentRequest,
        AlertEnrichmentWorkflowResult,
        EnrichedAlert,
        ThreatIntelResult,
    )

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


def _source_vendor_string(request: AlertEnrichmentRequest, key: str) -> str | None:
    source_event = request.case_input.source_event
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


def _source_ip_hints(request: AlertEnrichmentRequest) -> tuple[str | None, str | None]:
    source_ip = _source_vendor_string(request, "source_ip")
    destination_ip = _source_vendor_string(request, "destination_ip")

    source_event = request.case_input.source_event
    if source_event is None:
        return source_ip, destination_ip

    payload = source_event.payload
    raw_source_ip = getattr(payload, "source_ip", None)
    raw_destination_ip = getattr(payload, "destination_ip", None)

    if source_ip is None and isinstance(raw_source_ip, str) and raw_source_ip.strip():
        source_ip = raw_source_ip.strip()

    if destination_ip is None and isinstance(raw_destination_ip, str) and raw_destination_ip.strip():
        destination_ip = raw_destination_ip.strip()

    return source_ip, destination_ip


@workflow.defn
class AlertEnrichmentWorkflow:
    """Reusable child workflow for EDR alert enrichment and risk scoring."""

    @workflow.run
    async def run(self, request: AlertEnrichmentRequest) -> AlertEnrichmentWorkflowResult:
        case_input = request.case_input
        workflow.logger.info(
            "AlertEnrichmentWorkflow gestart — tenant=%s alert=%s",
            request.tenant_id,
            case_input.alert_id,
        )

        enrichment_context = {
            "case_type": case_input.case_type,
            "severity": case_input.severity,
            "identity": case_input.identity,
            "device": case_input.device,
            "indicator": request.threat_indicator,
        }

        enriched_payload: AlertEnrichmentResult = await workflow.execute_activity(
            edr_enrich_alert,
            args=[request.tenant_id, case_input.alert_id, enrichment_context],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
        user_email = (
            case_input.identity
            or _source_vendor_string(request, "user_email")
            or _source_vendor_string(request, "user_principal_name")
        )
        device_id = case_input.device or _source_vendor_string(request, "device_id")
        source_ip, destination_ip = _source_ip_hints(request)

        enriched = EnrichedAlert(
            alert_id=enriched_payload.alert_id or case_input.alert_id,
            severity=(enriched_payload.severity or case_input.severity).lower(),
            title=enriched_payload.title or f"SOC case {case_input.case_type}",
            description=str(enriched_payload.description or ""),
            user_display_name=(
                enriched_payload.user_display_name
                or user_email
            ),
            device_display_name=(
                enriched_payload.device_display_name
                or device_id
            ),
            user_department=enriched_payload.user_department,
            device_os=enriched_payload.device_os,
            device_compliance=enriched_payload.device_compliance,
        )

        if device_id:
            device_context = await workflow.execute_activity(
                edr_get_device_context,
                args=[request.tenant_id, device_id],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )

            if device_context:
                description = enriched.description
                if not enriched.device_display_name:
                    enriched = enriched.model_copy(update={"device_display_name": device_context.display_name})
                if not enriched.device_os and device_context.os_platform:
                    enriched = enriched.model_copy(update={"device_os": device_context.os_platform})
                if not enriched.device_compliance and device_context.compliance_state:
                    enriched = enriched.model_copy(update={"device_compliance": device_context.compliance_state})
                if device_context.risk_score:
                    description = f"{description}\nDevice risk score: {device_context.risk_score}"
                if description != enriched.description:
                    enriched = enriched.model_copy(update={"description": description})

        risky_lookup_key = user_email

        if risky_lookup_key:
            identity_risk = await workflow.execute_activity(
                identity_get_identity_risk,
                args=[request.tenant_id, str(risky_lookup_key)],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )

            if identity_risk and identity_risk.risk_level:
                enriched = enriched.model_copy(
                    update={
                        "description": f"{enriched.description}\nIdentity risk level: {identity_risk.risk_level}"
                    }
                )

        threat_intel = request.threat_intel or ThreatIntelResult(
            indicator=request.threat_indicator or source_ip or destination_ip or case_input.alert_id,
            is_malicious=False,
            provider="disabled",
            reputation_score=0.0,
            details="Threat intel disabled by tenant config.",
        )

        risk = await workflow.execute_activity(
            calculate_risk_score,
            args=[request.tenant_id, enriched, threat_intel],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        return AlertEnrichmentWorkflowResult(enriched_alert=enriched, risk_score=risk)
