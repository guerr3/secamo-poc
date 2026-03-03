import asyncio
import logging

from temporalio.client import Client, TLSConfig
from temporalio.worker import Worker

from shared.config import (
    TEMPORAL_ADDRESS,
    TEMPORAL_NAMESPACE,
    TEMPORAL_API_KEY,
    QUEUE_IAM,
    QUEUE_SOC,
    QUEUE_AUDIT,
)

# ── Activities ────────────────────────────────────────────────
from activities.tenant import validate_tenant_context, get_tenant_secrets
from activities.graph_users import (
    graph_get_user,
    graph_create_user,
    graph_update_user,
    graph_delete_user,
    graph_revoke_sessions,
    graph_assign_license,
    graph_reset_password,
)
from activities.graph_alerts import (
    graph_enrich_alert,
    graph_get_alerts,
    graph_isolate_device,
    threat_intel_lookup,
    calculate_risk_score,
)
from activities.ticketing import (
    ticket_create,
    ticket_update,
    ticket_close,
    ticket_get_details,
)
from activities.notifications import (
    teams_send_notification,
    teams_send_adaptive_card,
    email_send,
)
from activities.audit import create_audit_log, collect_evidence_bundle

# ── Workflows ─────────────────────────────────────────────────
from workflows.iam_onboarding import IamOnboardingWorkflow
from workflows.defender_alert_enrichment import DefenderAlertEnrichmentWorkflow
from workflows.impossible_travel import ImpossibleTravelWorkflow

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Gedeelde lijst van alle activities
ALL_ACTIVITIES = [
    # tenant
    validate_tenant_context,
    get_tenant_secrets,
    # graph users
    graph_get_user,
    graph_create_user,
    graph_update_user,
    graph_delete_user,
    graph_revoke_sessions,
    graph_assign_license,
    graph_reset_password,
    # graph alerts / SOC
    graph_enrich_alert,
    graph_get_alerts,
    graph_isolate_device,
    threat_intel_lookup,
    calculate_risk_score,
    # ticketing
    ticket_create,
    ticket_update,
    ticket_close,
    ticket_get_details,
    # notifications
    teams_send_notification,
    teams_send_adaptive_card,
    email_send,
    # audit
    create_audit_log,
    collect_evidence_bundle,
]


async def main() -> None:
    """Start workers voor alle task queues en verbind met Temporal Cloud."""
    mode = "Temporal Cloud (TLS + API key)" if TEMPORAL_API_KEY else "Self-hosted"
    logger.info(
        f"Verbinden met {mode} — {TEMPORAL_ADDRESS} "
        f"(namespace: {TEMPORAL_NAMESPACE})"
    )

    if TEMPORAL_API_KEY:
        # Temporal Cloud: TLS + API key vereist
        client = await Client.connect(
            TEMPORAL_ADDRESS,
            namespace=TEMPORAL_NAMESPACE,
            api_key=TEMPORAL_API_KEY,
            tls=True,
        )
    else:
        # Self-hosted: geen TLS, geen API key
        client = await Client.connect(
            TEMPORAL_ADDRESS,
            namespace=TEMPORAL_NAMESPACE,
        )

    logger.info(f"Verbinding met {mode} succesvol.")

    # Start één worker per task queue, alle draaien concurrent
    workers = [
        Worker(
            client,
            task_queue=QUEUE_IAM,
            workflows=[IamOnboardingWorkflow],
            activities=ALL_ACTIVITIES,
        ),
        Worker(
            client,
            task_queue=QUEUE_SOC,
            workflows=[
                DefenderAlertEnrichmentWorkflow,
                ImpossibleTravelWorkflow,
            ],
            activities=ALL_ACTIVITIES,
        ),
        Worker(
            client,
            task_queue=QUEUE_AUDIT,
            workflows=[],
            activities=ALL_ACTIVITIES,
        ),
    ]

    logger.info(
        f"Workers starten op queues: {QUEUE_IAM}, {QUEUE_SOC}, {QUEUE_AUDIT}"
    )

    # Draai alle workers tegelijkertijd
    async with asyncio.TaskGroup() as tg:
        for worker in workers:
            tg.create_task(worker.run())

    logger.info("Alle workers gestopt.")


if __name__ == "__main__":
    asyncio.run(main())
