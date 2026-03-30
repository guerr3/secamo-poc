from __future__ import annotations

import secrets as py_secrets
import string
from typing import Any, Optional
from urllib.parse import quote

import httpx
from temporalio import activity

from activities._activity_errors import application_error_from_http_status
from activities._tenant_secrets import load_tenant_secrets
from shared.graph_client import get_graph_token
from shared.models import GraphUser

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _retry_after_seconds(response: httpx.Response) -> int | None:
    retry_after = response.headers.get("Retry-After")
    if not retry_after:
        return None
    try:
        return int(retry_after)
    except ValueError:
        return None


def _handle_http_error(tenant_id: str, provider: str, response: httpx.Response, action: str) -> None:
    if response.status_code >= 400:
        raise application_error_from_http_status(
            tenant_id,
            provider,
            action,
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )


def _is_user_exists_conflict(status_code: int, body: dict) -> bool:
    if status_code == 409:
        return True
    if status_code != 400:
        return False

    error = body.get("error") if isinstance(body, dict) else None
    code = str((error or {}).get("code", "")).lower()
    message = str((error or {}).get("message", "")).lower()
    return "already" in message and "exist" in message or code in {
        "request_resourceexists",
        "resourceexists",
    }


def _generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(py_secrets.choice(alphabet) for _ in range(length))


@activity.defn
async def graph_get_user(tenant_id: str, email: str) -> Optional[GraphUser]:
    activity.logger.info(f"[{tenant_id}] graph_get_user: {email}")
    secrets = load_tenant_secrets(tenant_id, "graph")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(email)}?$select=id,displayName,mail,userPrincipalName,accountEnabled"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=_auth_headers(token))

    if response.status_code == 404:
        return None
    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_get_user")
    if response.status_code != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_get_user",
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )

    body = response.json()
    return GraphUser(
        user_id=body.get("id", ""),
        email=body.get("mail") or body.get("userPrincipalName") or email,
        display_name=body.get("displayName", ""),
        account_enabled=bool(body.get("accountEnabled", False)),
    )


@activity.defn
async def graph_create_user(tenant_id: str, user_data: dict[str, Any]) -> GraphUser:
    user_email = str(user_data.get("email", ""))
    first_name = str(user_data.get("first_name", ""))
    last_name = str(user_data.get("last_name", ""))
    department = str(user_data.get("department", ""))
    role = str(user_data.get("role", ""))

    activity.logger.info(f"[{tenant_id}] graph_create_user: {user_email}")
    secrets = load_tenant_secrets(tenant_id, "graph")
    token = await get_graph_token(secrets)
    temp_password = _generate_password(16)
    url = f"{GRAPH_BASE}/users"

    payload = {
        "accountEnabled": True,
        "displayName": f"{first_name} {last_name}".strip(),
        "mailNickname": user_email.split("@")[0] if "@" in user_email else user_email,
        "userPrincipalName": user_email,
        "department": department,
        "jobTitle": role,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": temp_password,
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=_auth_headers(token), json=payload)

    try:
        response_body = response.json()
    except Exception:
        response_body = {}
    if _is_user_exists_conflict(response.status_code, response_body):
        # Idempotent behavior: retries should resolve to the existing user record.
        existing_user = await graph_get_user(tenant_id, user_email)
        if existing_user is not None:
            return existing_user

    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_create_user")
    if response.status_code not in (200, 201, 202):
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_create_user",
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )

    body = response_body
    return GraphUser(
        user_id=body.get("id", ""),
        email=body.get("mail") or body.get("userPrincipalName") or user_email,
        display_name=body.get("displayName", f"{first_name} {last_name}".strip()),
        account_enabled=bool(body.get("accountEnabled", True)),
    )


@activity.defn
async def graph_update_user(tenant_id: str, user_id: str, updates: dict) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_update_user: {user_id}")
    secrets = load_tenant_secrets(tenant_id, "graph")
    token = await get_graph_token(secrets)
    patch_url = f"{GRAPH_BASE}/users/{quote(user_id)}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        patch_response = await client.patch(patch_url, headers=_auth_headers(token), json=updates)
    if patch_response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_graph", patch_response, "graph_update_user")
    if patch_response.status_code not in (200, 202, 204):
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_update_user",
            patch_response.status_code,
            retry_after_seconds=_retry_after_seconds(patch_response),
        )

    return True


@activity.defn
async def graph_delete_user(tenant_id: str, user_id: str) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_delete_user: {user_id}")
    secrets = load_tenant_secrets(tenant_id, "graph")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(user_id)}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.delete(url, headers=_auth_headers(token))

    if response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_delete_user")
    if response.status_code not in (200, 202, 204):
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_delete_user",
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )
    return True


@activity.defn
async def graph_revoke_sessions(tenant_id: str, user_id: str) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_revoke_sessions: {user_id}")
    secrets = load_tenant_secrets(tenant_id, "graph")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(user_id)}/revokeSignInSessions"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=_auth_headers(token))

    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_revoke_sessions")
    if response.status_code not in (200, 202, 204):
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_revoke_sessions",
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )
    return True


@activity.defn
async def graph_assign_license(tenant_id: str, user_id: str, sku_id: str) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_assign_license: {user_id}")
    secrets = load_tenant_secrets(tenant_id, "graph")
    token = await get_graph_token(secrets)
    url = f"{GRAPH_BASE}/users/{quote(user_id)}/assignLicense"
    payload = {
        "addLicenses": [{"skuId": sku_id}],
        "removeLicenses": [],
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=_auth_headers(token), json=payload)

    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_assign_license")
    if response.status_code not in (200, 201, 202, 204):
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_assign_license",
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )
    return True


@activity.defn
async def graph_reset_password(tenant_id: str, user_id: str, temp_password: str) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_reset_password: {user_id}")
    secrets = load_tenant_secrets(tenant_id, "graph")
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
    _handle_http_error(tenant_id, "microsoft_graph", response, "graph_reset_password")
    if response.status_code not in (200, 202, 204):
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_reset_password",
            response.status_code,
            retry_after_seconds=_retry_after_seconds(response),
        )
    return True
