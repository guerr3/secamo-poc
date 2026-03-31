"""Temporal worker bootstrap module.

Responsibility: load workflows/activities per queue and run worker processes.
This module must not contain ingress routing logic or provider webhook parsing.
"""

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
    QUEUE_POLLER,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_activities_by_queue() -> dict[str, list]:
    """Load activities and scope them to task queues."""
    iam_activities: list = []
    soc_activities: list = []
    audit_activities: list = []
    poller_activities: list = []

    try:
        from activities.tenant import (
            get_all_active_tenants,
            get_tenant_config,
            get_tenant_secrets,
            validate_tenant_context,
        )
        iam_activities.extend([validate_tenant_context, get_tenant_config, get_tenant_secrets])
        soc_activities.extend([validate_tenant_context, get_tenant_config, get_tenant_secrets, get_all_active_tenants])
        audit_activities.extend([validate_tenant_context, get_tenant_config, get_tenant_secrets])
        poller_activities.extend([get_tenant_config, get_tenant_secrets, get_all_active_tenants])
        logger.info("✓ Tenant activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Tenant activities: {e}")
        sys.exit(1)

    try:
        from activities.connector_dispatch import (
            subscription_create,
            subscription_delete,
            subscription_list,
            subscription_metadata_load,
            subscription_metadata_lookup,
            subscription_metadata_store,
            subscription_renew,
        )
        soc_activities.extend([
            subscription_create,
            subscription_renew,
            subscription_delete,
            subscription_list,
            subscription_metadata_store,
            subscription_metadata_load,
            subscription_metadata_lookup,
        ])
        logger.info("✓ Subscription capability activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Graph subscription activities: {e}")
        sys.exit(1)

    try:
        from activities.identity import (
            identity_assign_license,
            identity_create_user,
            identity_delete_user,
            identity_get_user,
            identity_reset_password,
            identity_revoke_sessions,
            identity_update_user,
        )
        iam_activities.extend([
            identity_get_user,
            identity_create_user,
            identity_update_user,
            identity_delete_user,
            identity_revoke_sessions,
            identity_assign_license,
            identity_reset_password,
        ])
        soc_activities.extend([
            identity_get_user,
            identity_delete_user,
            identity_revoke_sessions,
        ])
        logger.info("✓ Identity activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Identity activities: {e}")
        sys.exit(1)

    try:
        from activities.connector_dispatch import (
            device_get_context,
            graph_confirm_user_compromised,
            graph_dismiss_risky_user,
            graph_enrich_alert,
            graph_get_alerts,
            graph_get_signin_history,
            graph_isolate_device,
            graph_list_noncompliant_devices,
            graph_list_risky_users,
            graph_run_antivirus_scan,
            graph_unisolate_device,
            identity_get_risk_context,
        )
        from activities.threat_intel import threat_intel_lookup
        from activities.risk import calculate_risk_score
        soc_activities.extend([
            graph_enrich_alert,
            graph_get_alerts,
            graph_isolate_device,
            graph_unisolate_device,
            device_get_context,
            graph_run_antivirus_scan,
            graph_list_noncompliant_devices,
            identity_get_risk_context,
            graph_confirm_user_compromised,
            graph_dismiss_risky_user,
            graph_get_signin_history,
            graph_list_risky_users,
            threat_intel_lookup, calculate_risk_score,
        ])
        logger.info("✓ SOC capability activities geladen")
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
        from activities.communications import teams_send_notification, teams_send_adaptive_card, email_send
        soc_activities.extend([teams_send_notification, teams_send_adaptive_card, email_send])
        logger.info("✓ Communications activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Communications activities: {e}")
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
        poller_activities.extend([connector_fetch_events])
        logger.info("✓ Connector dispatch activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Connector dispatch activities: {e}")
        sys.exit(1)

    return {
        "iam": iam_activities,
        "soc": soc_activities,
        "audit": audit_activities,
        "poller": poller_activities,
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

    try:
        from workflows.graph_subscription_manager import GraphSubscriptionManagerWorkflow
        soc_workflows.extend([GraphSubscriptionManagerWorkflow])
        logger.info("✓ Graph ingress/subscription workflows geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Graph ingress/subscription workflows: {e}")
        sys.exit(1)

    poller_workflows = []
    try:
        from workflows.polling_manager import PollingManagerWorkflow
        poller_workflows.append(PollingManagerWorkflow)
        logger.info("✓ Polling Manager workflow geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Polling Manager Workflow: {e}")
        sys.exit(1)

    return {
        "iam":   iam_workflows,
        "soc":   soc_workflows,
        "audit": [],
        "poller": poller_workflows,
    }


async def main() -> None:
    """Start workers voor alle task queues en verbind met Temporal."""

    # 1. Valideer alle imports vóór netwerk connectie
    activities_map = load_activities_by_queue()
    workflows_map  = load_workflows()

    if (
        not activities_map["iam"]
        and not activities_map["soc"]
        and not activities_map["audit"]
        and not activities_map["poller"]
    ):
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
        Worker(client, task_queue=QUEUE_POLLER, workflows=workflows_map["poller"], activities=activities_map["poller"]),
    ]

    logger.info(f"Workers starten op queues: {QUEUE_IAM}, {QUEUE_SOC}, {QUEUE_AUDIT}, {QUEUE_POLLER}")

    async with asyncio.TaskGroup() as tg:
        for worker in workers:
            tg.create_task(worker.run())

    logger.info("Alle workers gestopt.")


if __name__ == "__main__":
    asyncio.run(main())
