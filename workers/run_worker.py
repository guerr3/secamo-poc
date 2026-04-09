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
from shared.routing.defaults import build_default_route_registry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _validate_route_worker_parity(workflows_map: dict[str, list]) -> None:
    """Fail fast when any configured route targets an unregistered workflow/queue."""
    queue_to_group = {
        QUEUE_IAM: "iam",
        QUEUE_SOC: "soc",
        QUEUE_AUDIT: "audit",
        QUEUE_POLLER: "poller",
    }
    known_queues = set(queue_to_group.keys())
    group_to_workflow_names = {
        group: {wf.__name__ for wf in workflows_map.get(group, [])}
        for group in ["iam", "soc", "audit", "poller"]
    }

    registry = build_default_route_registry()
    errors: list[str] = []

    for route in registry.iter_registered_routes():
        if route.task_queue not in known_queues:
            errors.append(
                f"unknown task queue '{route.task_queue}' for workflow '{route.workflow_name}'"
            )
            continue

        group = queue_to_group[route.task_queue]
        if route.workflow_name not in group_to_workflow_names.get(group, set()):
            errors.append(
                f"workflow '{route.workflow_name}' mapped to queue '{route.task_queue}' is not registered"
            )

    if errors:
        message = "route/worker parity validation failed: " + "; ".join(sorted(set(errors)))
        raise RuntimeError(message)


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
        from activities.onboarding import (
            provision_customer_secrets,
            register_customer_tenant,
        )
        iam_activities.extend([
            provision_customer_secrets,
            register_customer_tenant,
        ])
        logger.info("✓ Customer onboarding activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Customer onboarding activities: {e}")
        sys.exit(1)

    try:
        from activities.subscription import (
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
        from activities.edr import (
            edr_confirm_user_compromised,
            edr_dismiss_risky_user,
            edr_enrich_alert,
            edr_fetch_events,
            edr_get_device_context,
            edr_get_identity_risk,
            edr_get_signin_history,
            edr_get_user_alerts,
            edr_isolate_device,
            edr_list_noncompliant_devices,
            edr_list_risky_users,
            edr_run_antivirus_scan,
            edr_unisolate_device,
        )
        from activities.threat_intel import threat_intel_lookup, threat_intel_fanout
        from activities.risk import calculate_risk_score
        soc_activities.extend([
            edr_enrich_alert,
            edr_get_user_alerts,
            edr_isolate_device,
            edr_unisolate_device,
            edr_get_device_context,
            edr_run_antivirus_scan,
            edr_list_noncompliant_devices,
            edr_get_identity_risk,
            edr_confirm_user_compromised,
            edr_dismiss_risky_user,
            edr_get_signin_history,
            edr_list_risky_users,
            threat_intel_lookup, threat_intel_fanout, calculate_risk_score,
        ])
        poller_activities.extend([edr_fetch_events])
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
        from activities.provider_capabilities import (
            connector_execute_action,
            connector_health_check,
        )
        soc_activities.extend([
            connector_execute_action,
            connector_health_check,
        ])
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
        from workflows.customer_onboarding import CustomerOnboardingWorkflow
        from workflows.iam_onboarding import IamOnboardingWorkflow
        from workflows.child.user_deprovisioning import UserDeprovisioningWorkflow
        iam_workflows.extend([
            IamOnboardingWorkflow,
            CustomerOnboardingWorkflow,
            UserDeprovisioningWorkflow,
        ])
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
    _validate_route_worker_parity(workflows_map)

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
