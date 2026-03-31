from __future__ import annotations

import asyncio
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from activities.tenant import get_tenant_config
from shared.models import IdentityUser
from shared.providers.factory import get_identity_access_provider
from shared.ssm_client import get_secret_bundle


def _secret_type_for_iam_provider(iam_provider: str) -> str:
    normalized = iam_provider.strip().lower()
    if normalized in {"microsoft_graph", "entra_id"}:
        return "graph"
    return "identity"


async def _load_secret_bundle_async(tenant_id: str, secret_type: str) -> dict[str, str]:
    return await asyncio.to_thread(get_secret_bundle, tenant_id, secret_type)


async def _get_identity_provider(tenant_id: str):
    config = await get_tenant_config(tenant_id)
    secret_type = _secret_type_for_iam_provider(config.iam_provider)
    secrets = await _load_secret_bundle_async(tenant_id, secret_type)

    try:
        return await get_identity_access_provider(tenant_id, secrets, config)
    except NotImplementedError as exc:
        raise ApplicationError(
            f"identity provider '{config.iam_provider}' is not implemented for tenant '{tenant_id}'",
            type="IdentityProviderNotSupported",
            non_retryable=True,
        ) from exc
    except ValueError as exc:
        raise ApplicationError(
            f"identity provider config is invalid for tenant '{tenant_id}': {exc}",
            type="IdentityProviderConfigError",
            non_retryable=True,
        ) from exc


@activity.defn
async def identity_get_user(tenant_id: str, email: str) -> IdentityUser | None:
    provider = await _get_identity_provider(tenant_id)
    return await provider.get_user(email)


@activity.defn
async def identity_create_user(tenant_id: str, user_data: dict[str, Any]) -> IdentityUser:
    provider = await _get_identity_provider(tenant_id)
    return await provider.create_user(user_data)


@activity.defn
async def identity_update_user(tenant_id: str, user_id: str, updates: dict[str, Any]) -> bool:
    provider = await _get_identity_provider(tenant_id)
    return await provider.update_user(user_id, updates)


@activity.defn
async def identity_delete_user(tenant_id: str, user_id: str) -> bool:
    provider = await _get_identity_provider(tenant_id)
    return await provider.delete_user(user_id)


@activity.defn
async def identity_revoke_sessions(tenant_id: str, user_id: str) -> bool:
    provider = await _get_identity_provider(tenant_id)
    return await provider.revoke_sessions(user_id)


@activity.defn
async def identity_assign_license(tenant_id: str, user_id: str, sku_id: str) -> bool:
    provider = await _get_identity_provider(tenant_id)
    return await provider.assign_license(user_id, sku_id)


@activity.defn
async def identity_reset_password(tenant_id: str, user_id: str, temp_password: str) -> bool:
    provider = await _get_identity_provider(tenant_id)
    return await provider.reset_password(user_id, temp_password)
