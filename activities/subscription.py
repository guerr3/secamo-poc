"""Graph subscription management activities.

Activities remain thin wrappers around shared provider interfaces. All
connector/AWS I/O is delegated into shared.providers.
"""

from __future__ import annotations

from temporalio import activity

from activities._tenant_secrets import load_tenant_secrets
from activities.tenant import get_tenant_config
from shared.models.subscriptions import SubscriptionConfig, SubscriptionState
from shared.providers.factory import get_subscription_provider
from shared.providers.types import secret_type_for_provider
from shared.providers.subscription import lookup_subscription_metadata_record


async def _get_provider(tenant_id: str, secret_type: str):
    config = await get_tenant_config(tenant_id)
    provider_name = config.iam_provider
    resolved_secret_type = secret_type or "graph"
    try:
        resolved_secret_type = secret_type_for_provider(provider_name)
    except ValueError:
        resolved_secret_type = secret_type or "graph"

    secrets = load_tenant_secrets(tenant_id, resolved_secret_type)
    return await get_subscription_provider(
        tenant_id,
        secrets,
        provider=provider_name,
    )


@activity.defn
async def subscription_create(
    tenant_id: str,
    subscription: SubscriptionConfig,
    secret_type: str,
    notification_url: str,
    client_state: str,
) -> SubscriptionState:
    provider = await _get_provider(tenant_id, secret_type)
    return await provider.create_subscription(
        subscription,
        secret_type=secret_type,
        notification_url=notification_url,
        client_state=client_state,
    )


@activity.defn
async def subscription_renew(
    tenant_id: str,
    subscription_id: str,
    expiration_hours: int,
    secret_type: str,
) -> SubscriptionState:
    provider = await _get_provider(tenant_id, secret_type)
    return await provider.renew_subscription(
        subscription_id,
        expiration_hours=expiration_hours,
        secret_type=secret_type,
    )


@activity.defn
async def subscription_delete(tenant_id: str, subscription_id: str, secret_type: str) -> bool:
    provider = await _get_provider(tenant_id, secret_type)
    return await provider.delete_subscription(subscription_id, secret_type=secret_type)


@activity.defn
async def subscription_list(tenant_id: str, secret_type: str) -> list[SubscriptionState]:
    provider = await _get_provider(tenant_id, secret_type)
    return await provider.list_subscriptions(secret_type=secret_type)


@activity.defn
async def subscription_metadata_store(state: SubscriptionState) -> dict[str, object]:
    provider = await _get_provider(state.tenant_id, "graph")
    return await provider.store_metadata(state)


@activity.defn
async def subscription_metadata_load(tenant_id: str) -> list[SubscriptionState]:
    provider = await _get_provider(tenant_id, "graph")
    return await provider.load_metadata(tenant_id)


@activity.defn
async def subscription_metadata_lookup(subscription_id: str) -> SubscriptionState | None:
    return await lookup_subscription_metadata_record(subscription_id)
