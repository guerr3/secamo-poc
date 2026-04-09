from __future__ import annotations

import asyncio
from datetime import timedelta
import re
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError


with workflow.unsafe.imports_passed_through():
    from shared.config import QUEUE_INTERACTIONS    
    from activities.audit import create_audit_log
    from activities.communications import email_send, teams_send_notification
    from activities.onboarding import provision_customer_secrets, register_customer_tenant
    from activities.subscription import subscription_create, subscription_list
    from activities.tenant import get_tenant_config, get_tenant_secrets, validate_tenant_context
    from shared.models import TenantConfig, TicketResult
    from shared.models.canonical import CustomerOnboardingEvent, Envelope
    from shared.models.subscriptions import SubscriptionState
    from shared.workflow_helpers import create_soc_ticket


RETRY_POLICY = RetryPolicy(maximum_attempts=3)
TIMEOUT = timedelta(seconds=30)


def _resource_slug(resource: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", resource.strip().lower()).strip("-")
    return slug or "subscription"


def _is_partial_onboarding_enabled(payload: CustomerOnboardingEvent) -> bool:
    raw = payload.config.get("allow_partial_onboarding") if isinstance(payload.config, dict) else None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return False


@workflow.defn
class CustomerOnboardingWorkflow:
    """Tenant onboarding orchestration for secrets, registration, subscriptions and confirmations."""

    @workflow.run
    async def run(self, event: Envelope) -> str:
        if not isinstance(event.payload, CustomerOnboardingEvent):
            raise ValueError("CustomerOnboardingWorkflow requires customer.onboarding payload")

        payload = event.payload
        partial_onboarding = _is_partial_onboarding_enabled(payload)
        if payload.tenant_id != event.tenant_id:
            raise ApplicationError(
                "Envelope tenant_id and payload tenant_id must match",
                type="TenantMismatch",
                non_retryable=True,
            )

        if not payload.welcome_email:
            raise ApplicationError(
                "customer.onboarding requires payload.welcome_email",
                type="MissingWelcomeEmail",
                non_retryable=True,
            )

        workflow.logger.info("WF-CUST-ONBOARDING started tenant=%s", event.tenant_id)

        provisioning_result: dict[str, str] = await workflow.execute_activity(
            provision_customer_secrets,
            args=[event.tenant_id, payload],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        await workflow.execute_activity(
            register_customer_tenant,
            args=[event.tenant_id, payload],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        await workflow.execute_activity(
            validate_tenant_context,
            args=[event.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )

        config: TenantConfig = await workflow.execute_activity(
            get_tenant_config,
            args=[event.tenant_id],
            start_to_close_timeout=TIMEOUT,
            retry_policy=RETRY_POLICY,
        )
        runtime_retry = RetryPolicy(maximum_attempts=config.max_activity_attempts)

        await workflow.execute_activity(
            get_tenant_secrets,
            args=[event.tenant_id, "ticketing"],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        notification_url = str(provisioning_result.get("graph_notification_url") or "").strip()
        existing_keys: set[tuple[str, tuple[str, ...]]] = set()
        created_subscription_ids: list[str] = []
        has_desired_graph_subscriptions = bool(config.graph_subscriptions)

        if has_desired_graph_subscriptions and not notification_url:
            if partial_onboarding:
                workflow.logger.warning(
                    "WF-CUST-ONBOARDING partial mode: graph notification URL missing; skipping graph subscription bootstrap"
                )
            else:
                raise ApplicationError(
                    "Graph notification URL could not be resolved during onboarding provisioning",
                    type="MissingGraphNotificationUrl",
                    non_retryable=True,
                )

        if has_desired_graph_subscriptions and notification_url:
            existing_subscriptions: list[SubscriptionState] = await workflow.execute_activity(
                subscription_list,
                args=[event.tenant_id, "graph"],
                start_to_close_timeout=TIMEOUT,
                retry_policy=runtime_retry,
            )

            existing_keys = {
                (state.resource, tuple(sorted(state.change_types)))
                for state in existing_subscriptions
            }

            for desired in config.graph_subscriptions:
                key = (desired.resource, tuple(sorted(desired.change_types)))
                if key in existing_keys:
                    continue

                state: SubscriptionState = await workflow.execute_activity(
                    subscription_create,
                    args=[
                        event.tenant_id,
                        desired,
                        "graph",
                        notification_url,
                        f"secamo:{event.tenant_id}:{_resource_slug(desired.resource)}",
                    ],
                    start_to_close_timeout=TIMEOUT,
                    retry_policy=runtime_retry,
                )
                created_subscription_ids.append(state.subscription_id)
                existing_keys.add(key)

        analyst_email = payload.soc_analyst_email or config.soc_analyst_email
        if not analyst_email:
            raise ApplicationError(
                "No SOC analyst email configured for onboarding confirmation",
                type="MissingSocAnalystEmail",
                non_retryable=True,
            )

        display_name = payload.display_name or config.display_name or event.tenant_id
        teams_message = (
            f"Customer onboarding completed for tenant {event.tenant_id} ({display_name}). "
            f"Subscriptions created: {len(created_subscription_ids)}"
        )
        welcome_subject = f"Welcome to Secamo, {display_name}"
        welcome_body = (
            f"Hello,\n\n"
            f"Your Secamo onboarding for tenant '{event.tenant_id}' is completed.\n"
            f"SLA tier: {config.sla_tier}\n"
            f"Security subscriptions active: {len(existing_keys)}\n\n"
            f"Regards,\nSecamo MSSP"
        )

        teams_task = workflow.execute_activity(
            teams_send_notification,
            args=[event.tenant_id, "", teams_message],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
            task_queue=QUEUE_INTERACTIONS,
        )
        welcome_email_task = workflow.execute_activity(
            email_send,
            args=[event.tenant_id, payload.welcome_email, welcome_subject, welcome_body],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
            task_queue=QUEUE_INTERACTIONS,
        )
        ticket_task = create_soc_ticket(
            event.tenant_id,
            config,
            title=f"[ONBOARDING] {display_name}",
            description=(
                f"Tenant onboarding completed for {event.tenant_id}.\n"
                f"Customer: {display_name}\n"
                f"Analyst: {analyst_email}\n"
                f"Created subscriptions: {len(created_subscription_ids)}"
            ),
            severity="low",
            source_workflow="WF-CUST-ONBOARDING",
        )
        audit_task = workflow.execute_activity(
            create_audit_log,
            args=[
                event.tenant_id,
                workflow.info().workflow_id,
                "customer_onboarding",
                f"Customer onboarding completed for {display_name}",
                {
                    "event_id": event.event_id,
                    "requester": str(event.metadata.get("requester") or "onboarding-api"),
                    "created_subscription_ids": created_subscription_ids,
                },
            ],
            start_to_close_timeout=TIMEOUT,
            retry_policy=runtime_retry,
        )

        parallel_results = await asyncio.gather(
            teams_task,
            welcome_email_task,
            ticket_task,
            audit_task,
            return_exceptions=True,
        )

        errors = [item for item in parallel_results if isinstance(item, Exception)]
        if errors:
            first_error = errors[0]
            if isinstance(first_error, ApplicationError):
                raise first_error
            raise ApplicationError(
                f"Customer onboarding confirmation step failed: {type(first_error).__name__}",
                type="OnboardingConfirmationFailed",
                non_retryable=False,
            )

        ticket: TicketResult = parallel_results[2]  # type: ignore[assignment]

        result_msg = (
            f"Customer onboarding completed for tenant '{event.tenant_id}' "
            f"with ticket {ticket.ticket_id} and {len(created_subscription_ids)} new subscriptions."
        )
        workflow.logger.info(result_msg)
        return result_msg
