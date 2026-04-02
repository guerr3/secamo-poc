from __future__ import annotations

from datetime import datetime, timezone

import pytest

from activities.subscription import (
    subscription_create,
    subscription_delete,
    subscription_list,
    subscription_metadata_load,
    subscription_metadata_lookup,
    subscription_metadata_store,
    subscription_renew,
)
from shared.models.subscriptions import SubscriptionConfig, SubscriptionState


@pytest.fixture
def subscription_config() -> SubscriptionConfig:
    return SubscriptionConfig(resource="security/alerts_v2", change_types=["created", "updated"])


@pytest.fixture
def subscription_state() -> SubscriptionState:
    return SubscriptionState(
        subscription_id="sub-1",
        tenant_id="tenant-1",
        resource="security/alerts_v2",
        change_types=["created", "updated"],
        expires_at=datetime(2026, 4, 2, 12, 0, 0, tzinfo=timezone.utc),
        notification_url="https://example.test/hook",
        client_state="secamo:tenant-1:alerts",
    )


@pytest.mark.asyncio
async def test_subscription_create_delegates_to_provider(mocker, subscription_config, subscription_state):
    provider = mocker.AsyncMock()
    provider.create_subscription.return_value = subscription_state
    get_provider = mocker.patch("activities.subscription._get_provider", return_value=provider)

    result = await subscription_create(
        "tenant-1",
        subscription_config,
        "graph",
        "https://example.test/hook",
        "secamo:tenant-1:alerts",
    )

    assert result.subscription_id == "sub-1"
    get_provider.assert_awaited_once_with("tenant-1", "graph")
    provider.create_subscription.assert_awaited_once_with(
        subscription_config,
        secret_type="graph",
        notification_url="https://example.test/hook",
        client_state="secamo:tenant-1:alerts",
    )


@pytest.mark.asyncio
async def test_subscription_renew_delete_and_list_delegate(mocker, subscription_state):
    provider = mocker.AsyncMock()
    provider.renew_subscription.return_value = subscription_state
    provider.delete_subscription.return_value = True
    provider.list_subscriptions.return_value = [subscription_state]
    mocker.patch("activities.subscription._get_provider", return_value=provider)

    renewed = await subscription_renew("tenant-1", "sub-1", 24, "graph")
    deleted = await subscription_delete("tenant-1", "sub-1", "graph")
    listed = await subscription_list("tenant-1", "graph")

    assert renewed.subscription_id == "sub-1"
    assert deleted is True
    assert len(listed) == 1
    provider.renew_subscription.assert_awaited_once_with(
        "sub-1",
        expiration_hours=24,
        secret_type="graph",
    )
    provider.delete_subscription.assert_awaited_once_with("sub-1", secret_type="graph")
    provider.list_subscriptions.assert_awaited_once_with(secret_type="graph")


@pytest.mark.asyncio
async def test_subscription_metadata_store_and_load_delegate(mocker, subscription_state):
    provider = mocker.AsyncMock()
    provider.store_metadata.return_value = {
        "subscription_id": "sub-1",
        "tenant_id": "tenant-1",
        "resource": "security/alerts_v2",
        "change_types": ["created", "updated"],
    }
    provider.load_metadata.return_value = [subscription_state]
    mocker.patch("activities.subscription._get_provider", return_value=provider)

    stored = await subscription_metadata_store(subscription_state)
    loaded = await subscription_metadata_load("tenant-1")

    assert stored["subscription_id"] == "sub-1"
    assert stored["change_types"] == ["created", "updated"]
    assert len(loaded) == 1
    provider.store_metadata.assert_awaited_once_with(subscription_state)
    provider.load_metadata.assert_awaited_once_with("tenant-1")


@pytest.mark.asyncio
async def test_subscription_metadata_lookup_uses_provider_helper(mocker, subscription_state):
    lookup = mocker.patch(
        "activities.subscription.lookup_subscription_metadata_record",
        return_value=subscription_state,
    )

    result = await subscription_metadata_lookup("sub-1")

    assert result is subscription_state
    lookup.assert_awaited_once_with("sub-1")
