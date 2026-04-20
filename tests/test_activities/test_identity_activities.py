from __future__ import annotations

import pytest

from activities.identity import (
    identity_create_user,
    identity_assign_license,
    identity_disable_user,
    identity_delete_user,
    identity_get_user,
    identity_reset_password,
    identity_revoke_sessions,
    identity_update_user,
)
from shared.models import IdentityUser


@pytest.mark.asyncio
async def test_identity_get_user_maps_provider(mocker):
    provider = mocker.AsyncMock()
    provider.get_user.return_value = IdentityUser(
        identity_provider="microsoft_graph",
        user_id="u-1",
        email="john@example.com",
        display_name="John",
        account_enabled=True,
    )
    mocker.patch("activities.identity._get_identity_provider", return_value=provider)

    user = await identity_get_user("tenant-1", "john@example.com")

    assert user is not None
    assert user.user_id == "u-1"
    assert user.identity_provider == "microsoft_graph"
    provider.get_user.assert_awaited_once_with("john@example.com")


@pytest.mark.asyncio
async def test_identity_create_user_maps_provider(mocker):
    provider = mocker.AsyncMock()
    provider.create_user.return_value = IdentityUser(
        identity_provider="entra_id",
        user_id="u-2",
        email="jane@example.com",
        display_name="Jane",
        account_enabled=True,
    )
    mocker.patch("activities.identity._get_identity_provider", return_value=provider)

    created = await identity_create_user("tenant-1", {"email": "jane@example.com"})

    assert created.user_id == "u-2"
    assert created.identity_provider == "entra_id"
    provider.create_user.assert_awaited_once()


@pytest.mark.asyncio
async def test_identity_delete_and_revoke_delegate(mocker):
    provider = mocker.AsyncMock()
    provider.delete_user.return_value = True
    provider.revoke_sessions.return_value = True
    mocker.patch("activities.identity._get_identity_provider", return_value=provider)

    assert await identity_revoke_sessions("tenant-1", "u-1") is True
    assert await identity_delete_user("tenant-1", "u-1") is True

    provider.revoke_sessions.assert_awaited_once_with("u-1")
    provider.delete_user.assert_awaited_once_with("u-1")


@pytest.mark.asyncio
async def test_identity_update_assign_and_reset_delegate(mocker):
    provider = mocker.AsyncMock()
    provider.update_user.return_value = True
    provider.assign_license.return_value = True
    provider.reset_password.return_value = True
    mocker.patch("activities.identity._get_identity_provider", return_value=provider)

    assert await identity_update_user("tenant-1", "u-1", {"department": "SOC"}) is True
    assert await identity_assign_license("tenant-1", "u-1", "sku-1") is True
    assert await identity_reset_password("tenant-1", "u-1", "TempP@ss") is True

    provider.update_user.assert_awaited_once()
    provider.assign_license.assert_awaited_once_with("u-1", "sku-1")
    provider.reset_password.assert_awaited_once_with("u-1", "TempP@ss")


@pytest.mark.asyncio
async def test_identity_disable_user_by_user_id_updates_account_state(mocker):
    provider = mocker.AsyncMock()
    provider.update_user.return_value = True
    mocker.patch("activities.identity._get_identity_provider", return_value=provider)

    assert await identity_disable_user("tenant-1", "u-123") is True

    provider.get_user.assert_not_awaited()
    provider.update_user.assert_awaited_once_with("u-123", {"accountEnabled": False})


@pytest.mark.asyncio
async def test_identity_disable_user_by_email_resolves_then_disables(mocker):
    provider = mocker.AsyncMock()
    provider.get_user.return_value = IdentityUser(
        identity_provider="microsoft_graph",
        user_id="u-1",
        email="john@example.com",
        display_name="John",
        account_enabled=True,
    )
    provider.update_user.return_value = True
    mocker.patch("activities.identity._get_identity_provider", return_value=provider)

    assert await identity_disable_user("tenant-1", "john@example.com") is True

    provider.get_user.assert_awaited_once_with("john@example.com")
    provider.update_user.assert_awaited_once_with("u-1", {"accountEnabled": False})


@pytest.mark.asyncio
async def test_identity_disable_user_returns_false_when_email_not_found(mocker):
    provider = mocker.AsyncMock()
    provider.get_user.return_value = None
    mocker.patch("activities.identity._get_identity_provider", return_value=provider)

    assert await identity_disable_user("tenant-1", "missing@example.com") is False

    provider.get_user.assert_awaited_once_with("missing@example.com")
    provider.update_user.assert_not_awaited()
