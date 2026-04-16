from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy, WorkflowIDReusePolicy

with workflow.unsafe.imports_passed_through():
    from datetime import datetime, timezone
    from activities.audit import create_audit_log
    from activities.edr import edr_fetch_events
    from activities.polling_dedup import polling_mark_event_processed
    from activities.tenant import get_tenant_config
    from shared.models import PollingManagerInput, TenantConfig
    from shared.models.canonical import Envelope
    from shared.routing import build_default_route_registry
    from shared.workflow_helpers import start_child_workflow_idempotent

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)
_ROUTE_REGISTRY = build_default_route_registry()


def _as_utc(occurred_at: datetime | None) -> datetime | None:
    if occurred_at is None:
        return None
    if occurred_at.tzinfo is None:
        return occurred_at.replace(tzinfo=timezone.utc)
    return occurred_at.astimezone(timezone.utc)


def _extract_provider_event_id(event: Envelope) -> str | None:
    raw = event.metadata.get("provider_event_id")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()

    payload_alert_id = getattr(event.payload, "alert_id", None)
    if isinstance(payload_alert_id, str) and payload_alert_id.strip():
        return payload_alert_id.strip()

    return None


def _format_cursor(occurred_at: datetime | None, fallback: str | None) -> str | None:
    if occurred_at is None:
        return fallback
    return occurred_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def _child_workflow_id(
    *,
    provider: str,
    resource_type: str,
    tenant_id: str,
    dedup_event_id: str,
) -> str:
    normalized_event_id = (
        dedup_event_id.replace(" ", "_").replace("/", "_").replace("#", "_").strip()
    )
    return f"{provider}-{resource_type}-{tenant_id}-{normalized_event_id}"

@workflow.defn
class PollingManagerWorkflow:
    """Long-running polling loop for a tenant/provider/resource tuple via continue-as-new."""

    @workflow.run
    async def run(self, input: PollingManagerInput) -> str:
        workflow.logger.info(
            "PollingManager iter=%s tenant=%s provider=%s resource_type=%s cursor=%s",
            input.iteration,
            input.tenant_id,
            input.provider,
            input.resource_type,
            input.cursor,
        )

        effective_secret_type = input.secret_type
        effective_poll_interval = input.poll_interval_seconds

        config: TenantConfig = await workflow.execute_activity(
            get_tenant_config,
            args=[input.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        provider_cfg = next(
            (
                item
                for item in config.polling_providers
                if item.provider == input.provider and item.resource_type == input.resource_type
            ),
            None,
        )
        if provider_cfg is not None:
            effective_secret_type = provider_cfg.secret_type
            effective_poll_interval = provider_cfg.poll_interval_seconds

        fetch_result = await workflow.execute_activity(
            edr_fetch_events,
            args=[
                input.tenant_id,
                {
                    "provider": input.provider,
                    "since": input.cursor,
                    "resource_type": input.resource_type,
                    "top": 100,
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        fetched_count = len(fetch_result.data.events)
        new_count = 0
        dedup_skipped_count = 0
        fail_open_count = 0
        started_count = 0
        duplicate_start_count = 0
        unroutable_count = 0

        max_occurred_at: datetime | None = None
        for event in fetch_result.data.events:
            occurred = _as_utc(event.occurred_at)
            if occurred is not None and (max_occurred_at is None or occurred > max_occurred_at):
                max_occurred_at = occurred

            provider_event_id = _extract_provider_event_id(event)
            dedup_event_id = provider_event_id or event.event_id

            dedup_result = await workflow.execute_activity(
                polling_mark_event_processed,
                args=[
                    input.tenant_id,
                    input.provider,
                    input.resource_type,
                    event.payload.event_type,
                    dedup_event_id,
                    event.event_id,
                    provider_event_id,
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )

            if bool(dedup_result.get("fail_open")):
                fail_open_count += 1

            if not bool(dedup_result.get("is_new")):
                dedup_skipped_count += 1
                continue

            new_count += 1

            routes = _ROUTE_REGISTRY.resolve_polling(
                provider=input.provider,
                resource_type=input.resource_type,
                payload=event.payload,
            )
            if not routes:
                workflow.logger.warning(
                    "No polling route configured for provider=%s resource_type=%s event_id=%s",
                    input.provider,
                    input.resource_type,
                    event.event_id,
                )
                unroutable_count += 1
                continue

            route = routes[0]
            workflow_name = route.workflow_name
            task_queue = route.task_queue
            envelope = event
            child_workflow_id = _child_workflow_id(
                provider=input.provider,
                resource_type=input.resource_type,
                tenant_id=input.tenant_id,
                dedup_event_id=dedup_event_id,
            )

            child_started = await start_child_workflow_idempotent(
                workflow_name,
                envelope,
                workflow_id=child_workflow_id,
                task_queue=task_queue,
                parent_close_policy=workflow.ParentClosePolicy.ABANDON,
                id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            )
            if child_started:
                started_count += 1
            else:
                duplicate_start_count += 1

        new_cursor = _format_cursor(max_occurred_at, input.cursor)

        workflow.logger.info(
            (
                "PollingManager cycle stats tenant=%s provider=%s resource_type=%s iter=%s "
                "fetched=%s new=%s dedup_skipped=%s fail_open=%s "
                "started=%s duplicate_start=%s unroutable=%s cursor_in=%s cursor_out=%s"
            ),
            input.tenant_id,
            input.provider,
            input.resource_type,
            input.iteration,
            fetched_count,
            new_count,
            dedup_skipped_count,
            fail_open_count,
            started_count,
            duplicate_start_count,
            unroutable_count,
            input.cursor,
            new_cursor,
        )

        try:
            await workflow.execute_activity(
                create_audit_log,
                args=[
                    input.tenant_id,
                    workflow.info().workflow_id,
                    "polling_cycle",
                    (
                        f"fetched={fetched_count} new={new_count} dedup_skipped={dedup_skipped_count} "
                        f"started={started_count} duplicate_start={duplicate_start_count}"
                    ),
                    {
                        "provider": input.provider,
                        "resource_type": input.resource_type,
                        "iteration": input.iteration,
                        "fetched": fetched_count,
                        "new": new_count,
                        "dedup_skipped": dedup_skipped_count,
                        "fail_open": fail_open_count,
                        "started": started_count,
                        "duplicate_start": duplicate_start_count,
                        "unroutable": unroutable_count,
                        "cursor_in": input.cursor,
                        "cursor_out": new_cursor,
                    },
                ],
                start_to_close_timeout=TIMEOUT,
                retry_policy=RETRY_POLICY,
            )
        except Exception as exc:
            workflow.logger.warning("PollingManager cycle audit write failed: %s", exc)

        await workflow.sleep(timedelta(seconds=effective_poll_interval))

        workflow.continue_as_new(
            PollingManagerInput(
                tenant_id=input.tenant_id,
                provider=input.provider,
                resource_type=input.resource_type,
                secret_type=effective_secret_type,
                poll_interval_seconds=effective_poll_interval,
                cursor=new_cursor,
                iteration=input.iteration + 1,
            )
        )

        return "continue-as-new"
