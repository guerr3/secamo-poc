from __future__ import annotations

from datetime import datetime, timedelta, timezone

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from temporalio.exceptions import WorkflowAlreadyStartedError

    from activities.connector_dispatch import connector_fetch_events
    from activities.tenant import get_tenant_config, get_tenant_secrets
    from shared.models import PollingManagerInput, TenantConfig, TenantSecrets
    from shared.models.canonical import Correlation, Envelope, SecamoEventVariantAdapter, StoragePartition, derive_event_id
    from shared.models.mappers import resolve_polling_route

RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


def _canonical_event_to_envelope(event) -> Envelope:
    payload_data = {
        "event_type": event.event_type,
        "activity_id": 2004 if event.event_type == "defender.alert" else 3002,
        "activity_name": "polled_event",
        "alert_id": event.external_event_id or "",
        "title": event.subject,
        "description": str((event.payload or {}).get("description") or ""),
        "severity_id": 40,
        "severity": str(event.severity or "medium"),
    }

    if event.event_type == "defender.impossible_travel":
        payload_data = {
            "event_type": "defender.impossible_travel",
            "activity_id": 3002,
            "activity_name": "polled_event",
            "user_principal_name": str((event.payload or {}).get("user_email") or "unknown@example.com"),
            "source_ip": str((event.payload or {}).get("source_ip") or "0.0.0.0"),
            "destination_ip": (event.payload or {}).get("destination_ip"),
            "severity_id": 40,
            "severity": str(event.severity or "medium"),
        }

    payload = SecamoEventVariantAdapter.validate_python(payload_data)
    occurred_at = event.occurred_at or datetime.now(timezone.utc)
    correlation_id = event.request_id or event.external_event_id or "poller"

    return Envelope(
        event_id=derive_event_id(
            tenant_id=event.tenant_id,
            event_type=payload.event_type,
            occurred_at=occurred_at,
            correlation_id=correlation_id,
            provider_event_id=event.external_event_id,
        ),
        tenant_id=event.tenant_id,
        source_provider=event.provider,
        event_name=payload.event_type,
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=occurred_at,
        correlation=Correlation(
            correlation_id=correlation_id,
            causation_id=correlation_id,
            request_id=correlation_id,
            trace_id=correlation_id,
            storage_partition=StoragePartition(
                ddb_pk=f"TENANT#{event.tenant_id}",
                ddb_sk=f"EVENT#{payload.event_type.replace('.', '#')}#{event.external_event_id or 'poll'}",
                s3_bucket=f"secamo-events-{event.tenant_id}",
                s3_key_prefix=f"raw/{payload.event_type}/{event.external_event_id or 'poll'}",
            ),
        ),
        payload=payload,
        metadata={"provider_event_id": event.external_event_id or ""},
    )

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

        if input.iteration == 0:
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

        secrets: TenantSecrets = await workflow.execute_activity(
            get_tenant_secrets,
            args=[input.tenant_id, effective_secret_type],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        fetch_result = await workflow.execute_activity(
            connector_fetch_events,
            args=[
                input.tenant_id,
                input.provider,
                {
                    "since": input.cursor,
                    "resource_type": input.resource_type,
                    "top": 100,
                },
                secrets,
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        new_cursor = input.cursor
        for event in fetch_result.events:
            if event.occurred_at is not None:
                occurred = event.occurred_at
                if occurred.tzinfo is None:
                    occurred = occurred.replace(tzinfo=timezone.utc)
                else:
                    occurred = occurred.astimezone(timezone.utc)
                new_cursor = occurred.strftime("%Y-%m-%dT%H:%M:%SZ")

            route = resolve_polling_route(
                provider=input.provider,
                resource_type=input.resource_type,
                payload=event.payload,
            )
            if route is None:
                workflow.logger.warning(
                    "No polling route configured for provider=%s resource_type=%s event_id=%s",
                    input.provider,
                    input.resource_type,
                    event.external_event_id,
                )
                continue

            workflow_name, task_queue = route
            envelope = _canonical_event_to_envelope(event)
            event_id = event.external_event_id or envelope.event_id
            child_workflow_id = f"{input.provider}-{input.resource_type}-{input.tenant_id}-{event_id}"

            try:
                await workflow.start_child_workflow(
                    workflow_name,
                    envelope,
                    id=child_workflow_id,
                    task_queue=task_queue,
                    parent_close_policy=workflow.ParentClosePolicy.ABANDON,
                )
            except WorkflowAlreadyStartedError:
                workflow.logger.info("Duplicate event skipped via deterministic workflow_id=%s", child_workflow_id)

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
