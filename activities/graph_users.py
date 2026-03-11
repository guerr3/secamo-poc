from __future__ import annotations

import secrets as py_secrets
import string
from typing import Optional
from urllib.parse import quote

import httpx
from temporalio import activity

from shared.graph_client import get_graph_token
from shared.models import GraphUser, TenantSecrets, UserData

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _handle_http_error(tenant_id: str, provider: str, status: int, action: str) -> None:
    if status in (401, 403):
        raise RuntimeError(f"[{tenant_id}] Auth failed for {provider}: {status}")
    if status == 429:
        raise RuntimeError(f"[{tenant_id}] {provider} rate limited during {action}: {status}")
    if status >= 500:
        raise RuntimeError(f"[{tenant_id}] {provider} server error during {action}: {status}")


def _generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(py_secrets.choice(alphabet) for _ in range(length))


@activity.defn
async def graph_get_user(tenant_id: str, email: str, secrets: TenantSecrets) -> Optional[GraphUser]:
    activity.logger.info(f"[{tenant_id}] graph_get_user: {email}")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(email)}?$select=id,displayName,mail,userPrincipalName,accountEnabled"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=_auth_headers(token))

    if response.status_code == 404:
        return None
    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_get_user")
    if response.status_code != 200:
        raise RuntimeError(f"[{tenant_id}] graph_get_user failed: {response.status_code}")

    body = response.json()
    return GraphUser(
        user_id=body.get("id", ""),
        email=body.get("mail") or body.get("userPrincipalName") or email,
        display_name=body.get("displayName", ""),
        account_enabled=bool(body.get("accountEnabled", False)),
    )


@activity.defn
async def graph_create_user(tenant_id: str, user_data: UserData, secrets: TenantSecrets) -> GraphUser:
    activity.logger.info(f"[{tenant_id}] graph_create_user: {user_data.email}")
    token = await get_graph_token(secrets)
    temp_password = _generate_password(16)
    url = f"{GRAPH_BASE}/users"

    payload = {
        "accountEnabled": True,
        "displayName": f"{user_data.first_name} {user_data.last_name}",
        "mailNickname": user_data.email.split("@")[0],
        "userPrincipalName": user_data.email,
        "department": user_data.department,
        "jobTitle": user_data.role,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": temp_password,
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=_auth_headers(token), json=payload)

    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_create_user")
    if response.status_code not in (200, 201):
        raise RuntimeError(f"[{tenant_id}] graph_create_user failed: {response.status_code}")

    body = response.json()
    return GraphUser(
        user_id=body.get("id", ""),
        email=body.get("mail") or body.get("userPrincipalName") or user_data.email,
        display_name=body.get("displayName", f"{user_data.first_name} {user_data.last_name}"),
        account_enabled=bool(body.get("accountEnabled", True)),
    )


@activity.defn
async def graph_update_user(tenant_id: str, user_id: str, updates: dict, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_update_user: {user_id}")
    token = await get_graph_token(secrets)
    patch_url = f"{GRAPH_BASE}/users/{quote(user_id)}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        patch_response = await client.patch(patch_url, headers=_auth_headers(token), json=updates)
    if patch_response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_graph", patch_response.status_code, "graph_update_user")
    if patch_response.status_code not in (200, 204):
        raise RuntimeError(f"[{tenant_id}] graph_update_user failed: {patch_response.status_code}")

    return True


@activity.defn
async def graph_delete_user(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_delete_user: {user_id}")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(user_id)}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.delete(url, headers=_auth_headers(token))

    if response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_delete_user")
    if response.status_code != 204:
        raise RuntimeError(f"[{tenant_id}] graph_delete_user failed: {response.status_code}")
    return True


@activity.defn
async def graph_revoke_sessions(tenant_id: str, user_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_revoke_sessions: {user_id}")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(user_id)}/revokeSignInSessions"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=_auth_headers(token))

    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_revoke_sessions")
    if response.status_code not in (200, 204):
        raise RuntimeError(f"[{tenant_id}] graph_revoke_sessions failed: {response.status_code}")
    return True


@activity.defn
async def graph_assign_license(tenant_id: str, user_id: str, sku_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_assign_license: {user_id}")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(user_id)}/assignLicense"
    payload = {
        "addLicenses": [{"skuId": sku_id}],
        "removeLicenses": [],
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=_auth_headers(token), json=payload)

    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_assign_license")
    if response.status_code not in (200, 201):
        raise RuntimeError(f"[{tenant_id}] graph_assign_license failed: {response.status_code}")
    return True


@activity.defn
async def graph_reset_password(tenant_id: str, user_id: str, temp_password: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_reset_password: {user_id}")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(user_id)}"
    password_value = temp_password or _generate_password(16)

    payload = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": password_value,
        }
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.patch(url, headers=_auth_headers(token), json=payload)

    if response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_reset_password")
    if response.status_code not in (200, 204):
        raise RuntimeError(f"[{tenant_id}] graph_reset_password failed: {response.status_code}")
    return True
