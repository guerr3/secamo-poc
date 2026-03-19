from __future__ import annotations

from contextlib import asynccontextmanager
import time

import httpx

from shared.models import TenantSecrets


_TOKEN_CACHE: dict[str, dict[str, float | str]] = {}


def clear_token_cache() -> None:
    """Clear module-level token cache (tests only)."""
    _TOKEN_CACHE.clear()


def _cache_key(prefix: str, tenant_azure_id: str) -> str:
    return f"{prefix}:{tenant_azure_id}"


async def _fetch_oauth_token(secrets: TenantSecrets, scope: str) -> tuple[str, int]:
    token_url = f"https://login.microsoftonline.com/{secrets.tenant_azure_id}/oauth2/v2.0/token"
    payload = {
        "client_id": secrets.client_id,
        "client_secret": secrets.client_secret,
        "grant_type": "client_credentials",
        "scope": scope,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(token_url, data=payload)

    if response.status_code != 200:
        raise RuntimeError(f"OAuth token request failed with status={response.status_code}")

    body = response.json()
    token = body.get("access_token")
    if not token:
        raise RuntimeError("OAuth token response missing access_token")

    expires_in = int(body.get("expires_in", 3600))
    return token, expires_in


async def _get_scoped_token(secrets: TenantSecrets, scope: str, cache_prefix: str) -> str:
    key = _cache_key(cache_prefix, secrets.tenant_azure_id)
    now = time.time()
    cached = _TOKEN_CACHE.get(key)
    if cached and float(cached.get("expires_at", 0.0)) > now:
        return str(cached["token"])

    token, expires_in = await _fetch_oauth_token(secrets, scope)
    _TOKEN_CACHE[key] = {
        "token": token,
        "expires_at": now + expires_in - 300,
    }
    return token


async def get_graph_token(secrets: TenantSecrets) -> str:
    """Get a cached Microsoft Graph app token using client credentials."""
    return await _get_scoped_token(
        secrets=secrets,
        scope="https://graph.microsoft.com/.default",
        cache_prefix="graph",
    )


async def get_defender_token(secrets: TenantSecrets) -> str:
    """Get a cached Defender app token using client credentials."""
    return await _get_scoped_token(
        secrets=secrets,
        scope="https://api.securitycenter.microsoft.com/.default",
        cache_prefix="defender",
    )


@asynccontextmanager
async def get_graph_client(
    secrets: TenantSecrets,
    timeout: float = 30.0,
) -> httpx.AsyncClient:
    """Yield an AsyncClient configured with a valid Graph bearer token."""
    token = await get_graph_token(secrets)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
        yield client
