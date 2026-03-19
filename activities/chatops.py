from __future__ import annotations

import asyncio
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.tenant import get_tenant_config
from shared.models import ChatOpsAction, ChatOpsMessage
from shared.providers.factory import get_chatops_provider
from shared.ssm_client import get_secret_bundle


def _secret_type_from_credentials_path(path_template: str) -> str:
    """Extract SSM secret_type from a configured credentials path template."""
    normalized = path_template.replace("{tenant_id}", "tenant-placeholder").strip("/")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return "chatops"
    return parts[-1]


async def _load_secret_bundle_async(tenant_id: str, secret_type: str) -> dict[str, str]:
    """Load tenant secret bundle via thread offloading for boto3-backed calls."""
    return await asyncio.to_thread(get_secret_bundle, tenant_id, secret_type)


def _embed_workflow_metadata(
    tenant_id: str,
    workflow_id: str,
    run_id: str,
    actions: list[ChatOpsAction],
) -> list[ChatOpsAction]:
    """Add hidden workflow correlation fields to each action payload."""
    enriched: list[ChatOpsAction] = []
    for action in actions:
        merged_payload: dict[str, Any] = {
            **action.payload,
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "run_id": run_id,
            "action_taken": action.action_id,
        }
        enriched.append(
            ChatOpsAction(
                action_id=action.action_id,
                label=action.label,
                style=action.style,
                payload=merged_payload,
                requires_confirmation=action.requires_confirmation,
            )
        )
    return enriched


@activity.defn
async def send_interactive_alert(
    tenant_id: str,
    workflow_id: str,
    run_id: str,
    title: str,
    body: str,
    actions: list[ChatOpsAction],
    target_channel: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Send a standardized interactive ChatOps alert for analyst remediation.

    The activity enriches action payloads with workflow correlation metadata so
    inbound webhook handlers can signal the correct Temporal workflow execution.
    """
    cfg = await get_tenant_config(tenant_id)
    if not cfg.chatops_config.enabled:
        raise ApplicationError(
            f"ChatOps is disabled for tenant '{tenant_id}'",
            type="ChatOpsDisabled",
            non_retryable=True,
        )

    secret_type = _secret_type_from_credentials_path(cfg.chatops_config.credentials_path)
    secrets = await _load_secret_bundle_async(tenant_id, secret_type)
    if not secrets:
        raise ApplicationError(
            f"No ChatOps secrets found for tenant '{tenant_id}' and secret_type '{secret_type}'",
            type="MissingTenantSecrets",
            non_retryable=True,
        )

    provider = await get_chatops_provider(tenant_id, secrets)

    resolved_channel = target_channel or cfg.chatops_config.default_channel
    if not resolved_channel and cfg.chatops_config.default_channels:
        resolved_channel = cfg.chatops_config.default_channels[0]

    if not resolved_channel:
        raise ApplicationError(
            f"No ChatOps target channel configured for tenant '{tenant_id}'",
            type="MissingChatOpsChannel",
            non_retryable=True,
        )

    enriched_actions = _embed_workflow_metadata(
        tenant_id=tenant_id,
        workflow_id=workflow_id,
        run_id=run_id,
        actions=actions,
    )

    message = ChatOpsMessage(
        title=title,
        body=body,
        actions=enriched_actions,
        metadata={**(metadata or {}), "workflow_id": workflow_id, "run_id": run_id},
    )

    activity.logger.info(
        "[%s] send_interactive_alert provider=%s workflow_id=%s run_id=%s",
        tenant_id,
        cfg.chatops_config.provider_type,
        workflow_id,
        run_id,
    )
    return await provider.send_message(target_channel=resolved_channel, message=message)
