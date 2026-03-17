import asyncio
import logging
import sys

from temporalio.client import Client
from temporalio.contrib.pydantic import pydantic_data_converter
from temporalio.worker import Worker

from shared.config import (
    TEMPORAL_ADDRESS,
    TEMPORAL_NAMESPACE,
    QUEUE_IAM,
    QUEUE_SOC,
    QUEUE_AUDIT,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_activities_by_queue() -> dict[str, list]:
    """Load activities and scope them to task queues."""
    iam_activities: list = []
    soc_activities: list = []
    audit_activities: list = []

    try:
        from activities.tenant import validate_tenant_context, get_tenant_config, get_tenant_secrets
        iam_activities.extend([validate_tenant_context, get_tenant_config, get_tenant_secrets])
        soc_activities.extend([validate_tenant_context, get_tenant_config, get_tenant_secrets])
        audit_activities.extend([validate_tenant_context, get_tenant_config, get_tenant_secrets])
        logger.info("✓ Tenant activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Tenant activities: {e}")
        sys.exit(1)

    try:
        from activities.graph_users import (
            graph_get_user, graph_create_user, graph_update_user,
            graph_delete_user, graph_revoke_sessions,
            graph_assign_license, graph_reset_password,
        )
        iam_activities.extend([
            graph_get_user, graph_create_user, graph_update_user,
            graph_delete_user, graph_revoke_sessions,
            graph_assign_license, graph_reset_password,
        ])
        soc_activities.extend([
            graph_get_user,
            graph_delete_user,
            graph_revoke_sessions,
        ])
        logger.info("✓ Graph Users activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Graph Users activities: {e}")
        sys.exit(1)

    try:
        from activities.graph_alerts import (
            graph_enrich_alert, graph_get_alerts,
        )
        from activities.graph_devices import (
            graph_get_device_details,
            graph_isolate_device,
            graph_list_noncompliant_devices,
            graph_run_antivirus_scan,
            graph_unisolate_device,
        )
        from activities.graph_signin import (
            graph_confirm_user_compromised,
            graph_dismiss_risky_user,
            graph_get_risky_user,
            graph_get_signin_history,
            graph_list_risky_users,
        )
        from activities.threat_intel import threat_intel_lookup
        from activities.risk import calculate_risk_score
        soc_activities.extend([
            graph_enrich_alert,
            graph_get_alerts,
            graph_isolate_device,
            graph_unisolate_device,
            graph_get_device_details,
            graph_run_antivirus_scan,
            graph_list_noncompliant_devices,
            graph_get_risky_user,
            graph_confirm_user_compromised,
            graph_dismiss_risky_user,
            graph_get_signin_history,
            graph_list_risky_users,
            threat_intel_lookup, calculate_risk_score,
        ])
        logger.info("✓ Graph Alerts activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Graph Alerts activities: {e}")
        sys.exit(1)

    try:
        from activities.ticketing import (
            ticket_create, ticket_update, ticket_close, ticket_get_details,
        )
        soc_activities.extend([ticket_create, ticket_update, ticket_close, ticket_get_details])
        logger.info("✓ Ticketing activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Ticketing activities: {e}")
        sys.exit(1)

    try:
        from activities.notify_teams import teams_send_notification, teams_send_adaptive_card
        from activities.notify_email import email_send
        soc_activities.extend([teams_send_notification, teams_send_adaptive_card, email_send])
        logger.info("✓ Notifications activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Notifications activities: {e}")
        sys.exit(1)

    try:
        from activities.hitl import request_hitl_approval
        soc_activities.append(request_hitl_approval)
        logger.info("✓ HiTL activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van HiTL activities: {e}")
        sys.exit(1)

    try:
        from activities.audit import create_audit_log
        from activities.evidence import collect_evidence_bundle
        iam_activities.append(create_audit_log)
        soc_activities.extend([create_audit_log, collect_evidence_bundle])
        audit_activities.extend([create_audit_log, collect_evidence_bundle])
        logger.info("✓ Audit activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Audit activities: {e}")
        sys.exit(1)

    try:
        from activities.connector_dispatch import (
            connector_fetch_events,
            connector_execute_action,
            connector_health_check,
            connector_threat_intel_fanout,
        )
        soc_activities.extend([
            connector_fetch_events,
            connector_execute_action,
            connector_health_check,
            connector_threat_intel_fanout,
        ])
        logger.info("✓ Connector dispatch activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Connector dispatch activities: {e}")
        sys.exit(1)

    return {
        "iam": iam_activities,
        "soc": soc_activities,
        "audit": audit_activities,
    }


def load_workflows() -> dict:
    """Lazy load all workflows met expliciete foutafhandeling."""
    iam_workflows = []
    try:
        from workflows.iam_onboarding import IamOnboardingWorkflow
        from workflows.child.user_deprovisioning import UserDeprovisioningWorkflow
        iam_workflows.extend([IamOnboardingWorkflow, UserDeprovisioningWorkflow])
        logger.info("✓ IAM Onboarding workflow geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van IAM Onboarding Workflow: {e}")
        sys.exit(1)

    soc_workflows = []
    try:
        from workflows.defender_alert_enrichment import DefenderAlertEnrichmentWorkflow
        from workflows.child.alert_enrichment import AlertEnrichmentWorkflow
        from workflows.child.hitl_approval import HiTLApprovalWorkflow
        from workflows.child.incident_response import IncidentResponseWorkflow
        from workflows.child.threat_intel_enrichment import ThreatIntelEnrichmentWorkflow
        from workflows.child.ticket_creation import TicketCreationWorkflow
        soc_workflows.extend([
            DefenderAlertEnrichmentWorkflow,
            ThreatIntelEnrichmentWorkflow,
            AlertEnrichmentWorkflow,
            TicketCreationWorkflow,
            HiTLApprovalWorkflow,
            IncidentResponseWorkflow,
        ])
        logger.info("✓ Defender Alert Enrichment workflow geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Defender Alert Enrichment Workflow: {e}")
        sys.exit(1)

    try:
        from workflows.impossible_travel import ImpossibleTravelWorkflow
        soc_workflows.append(ImpossibleTravelWorkflow)
        logger.info("✓ Impossible Travel workflow geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Impossible Travel Workflow: {e}")
        sys.exit(1)

    return {
        "iam":   iam_workflows,
        "soc":   soc_workflows,
        "audit": [],
    }


async def main() -> None:
    """Start workers voor alle task queues en verbind met Temporal."""

    # 1. Valideer alle imports vóór netwerk connectie
    activities_map = load_activities_by_queue()
    workflows_map  = load_workflows()

    if not activities_map["iam"] and not activities_map["soc"] and not activities_map["audit"]:
        logger.error("✗ Geen activiteiten ingeladen — worker wordt niet gestart.")
        sys.exit(1)

    # 2. Verbinden met Temporal
    logger.info(f"Verbinden met self-hosted Temporal — {TEMPORAL_ADDRESS} (namespace: {TEMPORAL_NAMESPACE})")

    client = await Client.connect(
        TEMPORAL_ADDRESS,
        namespace=TEMPORAL_NAMESPACE,
        data_converter=pydantic_data_converter,
    )

    logger.info("✓ Verbinding met self-hosted Temporal succesvol.")

    # 3. Workers starten
    workers = [
        Worker(client, task_queue=QUEUE_IAM,   workflows=workflows_map["iam"],   activities=activities_map["iam"]),
        Worker(client, task_queue=QUEUE_SOC,   workflows=workflows_map["soc"],   activities=activities_map["soc"]),
        Worker(client, task_queue=QUEUE_AUDIT, workflows=workflows_map["audit"], activities=activities_map["audit"]),
    ]

    logger.info(f"Workers starten op queues: {QUEUE_IAM}, {QUEUE_SOC}, {QUEUE_AUDIT}")

    async with asyncio.TaskGroup() as tg:
        for worker in workers:
            tg.create_task(worker.run())

    logger.info("Alle workers gestopt.")


if __name__ == "__main__":
    asyncio.run(main())
