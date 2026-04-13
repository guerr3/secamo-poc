from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

from activities.tenant import get_tenant_config, validate_tenant_context
from shared.config import QUEUE_EDR, QUEUE_TICKETING
from shared.models import TenantConfig, ThreatIntelResult, TicketResult


async def bootstrap_tenant(
    tenant_id: str,
    retry_policy: RetryPolicy,
    timeout: timedelta,
) -> TenantConfig:
    """Validate tenant and fetch runtime config without loading tenant secrets."""
    await workflow.execute_activity(
        validate_tenant_context,
        args=[tenant_id],
        start_to_close_timeout=timeout,
        retry_policy=retry_policy,
    )

    return await workflow.execute_activity(
        get_tenant_config,
        args=[tenant_id],
        start_to_close_timeout=timeout,
        retry_policy=retry_policy,
    )


async def resolve_threat_intel(
    tenant_id: str,
    indicator: str,
    config: TenantConfig,
    *,
    task_queue: str = QUEUE_EDR,
) -> ThreatIntelResult:
    """Run threat-intel enrichment through child workflow or return disabled fallback."""
    if not config.threat_intel_enabled:
        return ThreatIntelResult(
            indicator=indicator,
            is_malicious=False,
            provider="disabled",
            reputation_score=0.0,
            details="Threat intel disabled by tenant config.",
        )

    from shared.models import ThreatIntelEnrichmentRequest
    from workflows.child.threat_intel_enrichment import ThreatIntelEnrichmentWorkflow

    return await workflow.execute_child_workflow(
        ThreatIntelEnrichmentWorkflow.run,
        ThreatIntelEnrichmentRequest(
            tenant_id=tenant_id,
            indicator=indicator,
            providers=config.threat_intel_providers,
        ),
        id=f"{workflow.info().workflow_id}-ti",
        task_queue=task_queue,
    )


async def create_soc_ticket(
    tenant_id: str,
    config: TenantConfig,
    *,
    title: str,
    description: str,
    severity: str,
    source_workflow: str,
    task_queue: str = QUEUE_TICKETING,
) -> TicketResult:
    """Create a SOC ticket via reusable child workflow orchestration."""
    from shared.models import TicketCreationRequest
    from workflows.child.ticket_creation import TicketCreationWorkflow

    return await workflow.execute_child_workflow(
        TicketCreationWorkflow.run,
        TicketCreationRequest(
            tenant_id=tenant_id,
            title=title,
            description=description,
            severity=severity,
            source_workflow=source_workflow,
            ticketing_provider=config.ticketing_provider,
        ),
        id=f"{workflow.info().workflow_id}-ticket",
        task_queue=task_queue,
    )


async def start_child_workflow_idempotent(
    child_workflow: Any,
    child_input: Any,
    *,
    workflow_id: str,
    task_queue: str,
    parent_close_policy: workflow.ParentClosePolicy = workflow.ParentClosePolicy.ABANDON,
) -> None:
    """Start child workflow while tolerating deterministic duplicate starts."""
    from temporalio.exceptions import WorkflowAlreadyStartedError

    try:
        await workflow.start_child_workflow(
            child_workflow,
            child_input,
            id=workflow_id,
            task_queue=task_queue,
            parent_close_policy=parent_close_policy,
        )
    except WorkflowAlreadyStartedError:
        workflow.logger.info("Child workflow already running: %s", workflow_id)


async def emit_workflow_observability(
    tenant_id: str,
    *,
    workflow_id: str,
    action: str,
    result: str,
    metadata: dict[str, Any],
    timeout: timedelta,
    retry_policy: RetryPolicy,
    notification_message: str | None = None,
) -> None:
    """Write best-effort Teams + audit observability without failing orchestration."""
    from activities.audit import create_audit_log
    from activities.communications import teams_send_notification

    if notification_message:
        try:
            await workflow.execute_activity(
                teams_send_notification,
                args=[tenant_id, "", notification_message],
                start_to_close_timeout=timeout,
                retry_policy=retry_policy,
            )
        except Exception as exc:
            workflow.logger.warning("Teams notification failed, continuing workflow: %s", exc)

    try:
        await workflow.execute_activity(
            create_audit_log,
            args=[tenant_id, workflow_id, action, result, metadata],
            start_to_close_timeout=timeout,
            retry_policy=retry_policy,
        )
    except Exception as exc:
        workflow.logger.warning("Audit log write failed, continuing workflow: %s", exc)
