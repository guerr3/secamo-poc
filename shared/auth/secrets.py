"""Secret and JWKS resolution utilities with bounded in-memory caching.

Responsibility: provide reusable resolver primitives for validator implementations.
This module must not contain provider-specific validation rules or workflow dispatch logic.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.request import urlopen

import boto3
from botocore.exceptions import ClientError


@runtime_checkable
class SecretFetcher(Protocol):
    """Fetcher protocol for secure parameter retrieval backends."""

    def fetch_secret(self, full_path: str) -> str | None:
        """Fetch one secret value for a fully-qualified parameter path."""


@runtime_checkable
class JwksFetcher(Protocol):
    """Fetcher protocol for JWKS document retrieval backends."""

    def fetch_jwks(self, jwks_url: str) -> dict[str, Any] | None:
        """Fetch a JWKS document for signature verification."""


class Boto3SecretFetcher:
    """Default SSM-based secret fetcher used by cached resolver."""

    def __init__(self, region_name: str = "eu-west-1") -> None:
        self._ssm = boto3.client("ssm", region_name=region_name)

    def fetch_secret(self, full_path: str) -> str | None:
        try:
            response = self._ssm.get_parameter(Name=full_path, WithDecryption=True)
            return str(response.get("Parameter", {}).get("Value", ""))
        except self._ssm.exceptions.ParameterNotFound:
            return None
        except ClientError:
            return None


class UrlopenJwksFetcher:
    """Default urllib-based JWKS document fetcher used by cached resolver."""

    def fetch_jwks(self, jwks_url: str) -> dict[str, Any] | None:
        try:
            with urlopen(jwks_url, timeout=5) as response:
                if response.status != 200:
                    return None
                payload = json.loads(response.read().decode("utf-8"))
                if isinstance(payload, dict):
                    return payload
                return None
        except Exception:
            return None


@dataclass(frozen=True)
class _CacheEntry:
    value: Any
    expires_at: float


class CachedSecretResolver:
    """Resolver with TTL caching for secret and JWKS retrieval operations."""

    def __init__(
        self,
        secret_fetcher: SecretFetcher | None = None,
        jwks_fetcher: JwksFetcher | None = None,
        *,
        default_secret_ttl_seconds: int = 300,
        default_jwks_ttl_seconds: int = 3600,
        time_provider: callable | None = None,
    ) -> None:
        self._secret_fetcher = secret_fetcher or Boto3SecretFetcher()
        self._jwks_fetcher = jwks_fetcher or UrlopenJwksFetcher()
        self._default_secret_ttl_seconds = default_secret_ttl_seconds
        self._default_jwks_ttl_seconds = default_jwks_ttl_seconds
        self._time = time_provider or time.time
        self._cache: dict[str, _CacheEntry] = {}

    def _cache_key(self, namespace: str, name: str) -> str:
        return f"{namespace}:{name}"

    def _load_from_cache(self, key: str) -> Any | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        now = float(self._time())
        if now >= entry.expires_at:
            self._cache.pop(key, None)
            return None
        return entry.value

    def _store_in_cache(self, key: str, value: Any, ttl_seconds: int) -> Any:
        expires_at = float(self._time()) + max(0, ttl_seconds)
        self._cache[key] = _CacheEntry(value=value, expires_at=expires_at)
        return value

    def invalidate(self, key: str) -> None:
        """Invalidate one cache key.

        Accepted keys are either fully-qualified cache keys (secret:/path) or
        raw parameter paths/JWKS urls which are auto-expanded to both namespaces.
        """

        if key.startswith("secret:") or key.startswith("jwks:"):
            self._cache.pop(key, None)
            return
        self._cache.pop(self._cache_key("secret", key), None)
        self._cache.pop(self._cache_key("jwks", key), None)

    def get_secret(self, full_path: str, ttl_seconds: int | None = None) -> str | None:
        """Return cached secret value for a fully-qualified SSM path."""

        cache_key = self._cache_key("secret", full_path)
        cached = self._load_from_cache(cache_key)
        if cached is not None:
            return str(cached)

        value = self._secret_fetcher.fetch_secret(full_path)
        if value is None:
            return None
        ttl = self._default_secret_ttl_seconds if ttl_seconds is None else ttl_seconds
        return str(self._store_in_cache(cache_key, value, ttl))

    def get_tenant_secret(self, tenant_id: str, relative_path: str, ttl_seconds: int | None = None) -> str | None:
        """Return cached secret value using tenant-relative path resolution."""

        normalized_relative = relative_path.lstrip("/")
        full_path = f"/secamo/tenants/{tenant_id}/{normalized_relative}".replace("//", "/")
        return self.get_secret(full_path=full_path, ttl_seconds=ttl_seconds)

    def get_jwks(self, jwks_url: str, ttl_seconds: int | None = None) -> dict[str, Any] | None:
        """Return cached JWKS payload for provided URL."""

        cache_key = self._cache_key("jwks", jwks_url)
        cached = self._load_from_cache(cache_key)
        if cached is not None:
            if isinstance(cached, dict):
                return cached
            return None

        payload = self._jwks_fetcher.fetch_jwks(jwks_url)
        if payload is None:
            return None

        ttl = self._default_jwks_ttl_seconds if ttl_seconds is None else ttl_seconds
        stored = self._store_in_cache(cache_key, payload, ttl)
        if isinstance(stored, dict):
            return stored
        return None
