from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from activities.connector_dispatch import connector_execute_action
    from activities.graph_devices import graph_get_device_details
    from activities.graph_signin import graph_get_risky_user
    from activities.risk import calculate_risk_score
    from shared.models import (
        AlertEnrichmentRequest,
        AlertEnrichmentResult,
        ConnectorActionResult,
        EnrichedAlert,
        ThreatIntelResult,
    )

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


@workflow.defn
class AlertEnrichmentWorkflow:
    """Reusable child workflow for EDR alert enrichment and risk scoring."""

    @workflow.run
    async def run(self, request: AlertEnrichmentRequest) -> AlertEnrichmentResult:
        workflow.logger.info(
            "AlertEnrichmentWorkflow gestart — tenant=%s alert=%s",
            request.tenant_id,
            request.alert.alert_id,
        )

        enrich_result: ConnectorActionResult = await workflow.execute_activity(
            connector_execute_action,
            args=[
                request.tenant_id,
                request.edr_provider,
                "enrich_alert",
                {"alert_id": request.alert.alert_id},
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        enriched_payload = enrich_result.data.payload
        user_email_ext = request.alert.vendor_extensions.get("user_email")
        device_id_ext = request.alert.vendor_extensions.get("device_id")
        source_ip_ext = request.alert.vendor_extensions.get("source_ip")
        destination_ip_ext = request.alert.vendor_extensions.get("destination_ip")
        user_email = str(user_email_ext.value) if user_email_ext and user_email_ext.value else None
        device_id = str(device_id_ext.value) if device_id_ext and device_id_ext.value else None
        source_ip = str(source_ip_ext.value) if source_ip_ext and source_ip_ext.value else None
        destination_ip = str(destination_ip_ext.value) if destination_ip_ext and destination_ip_ext.value else None

        enriched = EnrichedAlert(
            alert_id=enriched_payload.get("id", request.alert.alert_id),
            severity=(enriched_payload.get("severity") or request.alert.severity).lower(),
            title=enriched_payload.get("title", request.alert.title),
            description=str(enriched_payload.get("description") or request.alert.description or ""),
            user_display_name=(
                (enriched_payload.get("userStates") or [{}])[0].get("userPrincipalName")
                if enriched_payload.get("userStates")
                else user_email
            ),
            device_display_name=(
                (enriched_payload.get("deviceEvidence") or [{}])[0].get("deviceDnsName")
                if enriched_payload.get("deviceEvidence")
                else device_id
            ),
        )

        if device_id:
            device_details = await workflow.execute_activity(
                graph_get_device_details,
                args=[request.tenant_id, device_id],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            if device_details:
                description = enriched.description
                if not enriched.device_display_name:
                    enriched = enriched.model_copy(update={"device_display_name": device_details.computerDnsName})
                if not enriched.device_os and device_details.osPlatform:
                    enriched = enriched.model_copy(update={"device_os": device_details.osPlatform})
                if device_details.riskScore:
                    description = f"{description}\nDevice risk score: {device_details.riskScore}"
                if description != enriched.description:
                    enriched = enriched.model_copy(update={"description": description})

        risky_lookup_key = (
            (enriched_payload.get("userStates") or [{}])[0].get("userId")
            if enriched_payload.get("userStates")
            else None
        ) or user_email

        if risky_lookup_key:
            risky_user = await workflow.execute_activity(
                graph_get_risky_user,
                args=[request.tenant_id, risky_lookup_key],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
            if risky_user and risky_user.riskLevel:
                enriched = enriched.model_copy(
                    update={
                        "description": f"{enriched.description}\nIdentity Protection risk level: {risky_user.riskLevel}"
                    }
                )

        threat_intel = request.threat_intel or ThreatIntelResult(
            indicator=source_ip or destination_ip or "",
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

        return AlertEnrichmentResult(enriched_alert=enriched, risk_score=risk)
