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


def load_activities() -> list:
    """Lazy load all activities met expliciete foutafhandeling."""
    activities = []

    try:
        from activities.tenant import validate_tenant_context, get_tenant_secrets
        activities.extend([validate_tenant_context, get_tenant_secrets])
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
        activities.extend([
            graph_get_user, graph_create_user, graph_update_user,
            graph_delete_user, graph_revoke_sessions,
            graph_assign_license, graph_reset_password,
        ])
        logger.info("✓ Graph Users activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Graph Users activities: {e}")
        sys.exit(1)

    try:
        from activities.graph_alerts import (
            graph_enrich_alert, graph_get_alerts, graph_isolate_device,
            threat_intel_lookup, calculate_risk_score,
        )
        activities.extend([
            graph_enrich_alert, graph_get_alerts, graph_isolate_device,
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
        activities.extend([ticket_create, ticket_update, ticket_close, ticket_get_details])
        logger.info("✓ Ticketing activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Ticketing activities: {e}")
        sys.exit(1)

    try:
        from activities.notifications import (
            teams_send_notification, teams_send_adaptive_card, email_send,
        )
        activities.extend([teams_send_notification, teams_send_adaptive_card, email_send])
        logger.info("✓ Notifications activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Notifications activities: {e}")
        sys.exit(1)

    try:
        from activities.audit import create_audit_log, collect_evidence_bundle
        activities.extend([create_audit_log, collect_evidence_bundle])
        logger.info("✓ Audit activities geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van Audit activities: {e}")
        sys.exit(1)

    return activities


def load_workflows() -> dict:
    """Lazy load all workflows met expliciete foutafhandeling."""
    iam_workflows = []
    try:
        from workflows.iam_onboarding import IamOnboardingWorkflow
        iam_workflows.append(IamOnboardingWorkflow)
        logger.info("✓ IAM Onboarding workflow geladen")
    except ImportError as e:
        logger.error(f"✗ Fout bij het laden van IAM Onboarding Workflow: {e}")
        sys.exit(1)

    soc_workflows = []
    try:
        from workflows.defender_alert_enrichment import DefenderAlertEnrichmentWorkflow
        soc_workflows.append(DefenderAlertEnrichmentWorkflow)
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
    all_activities = load_activities()
    workflows_map  = load_workflows()

    if not all_activities:
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
        Worker(client, task_queue=QUEUE_IAM,   workflows=workflows_map["iam"],   activities=all_activities),
        Worker(client, task_queue=QUEUE_SOC,   workflows=workflows_map["soc"],   activities=all_activities),
        Worker(client, task_queue=QUEUE_AUDIT, workflows=workflows_map["audit"], activities=all_activities),
    ]

    logger.info(f"Workers starten op queues: {QUEUE_IAM}, {QUEUE_SOC}, {QUEUE_AUDIT}")

    async with asyncio.TaskGroup() as tg:
        for worker in workers:
            tg.create_task(worker.run())

    logger.info("Alle workers gestopt.")


if __name__ == "__main__":
    asyncio.run(main())
