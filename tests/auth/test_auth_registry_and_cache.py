"""Phase-2 verification for auth registry and cache semantics.

Responsibility: validate fail-closed registry behavior and resolver cache/rotation behavior.
This module must not test ingress routing or workflow execution.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from shared.auth.contracts import AuthValidationRequest
from shared.auth.registry import AuthValidatorRegistry, build_default_validator_registry
from shared.auth.secrets import CachedSecretResolver


class _MutableClock:
    def __init__(self) -> None:
        self.current = 100.0

    def now(self) -> float:
        return self.current


class _CountingSecretFetcher:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.calls = 0

    def fetch_secret(self, full_path: str) -> str | None:
        self.calls += 1
        return self.values.get(full_path)


class _CountingJwksFetcher:
    def __init__(self, values: dict[str, dict]) -> None:
        self.values = values
        self.calls = 0

    def fetch_jwks(self, jwks_url: str) -> dict | None:
        self.calls += 1
        return self.values.get(jwks_url)


def test_secret_cache_ttl_and_invalidation_support_rotation() -> None:
    clock = _MutableClock()
    secret_path = "/secamo/tenants/t-1/webhooks/jira_secret"
    fetcher = _CountingSecretFetcher({secret_path: "v1"})

    resolver = CachedSecretResolver(
        secret_fetcher=fetcher,
        jwks_fetcher=_CountingJwksFetcher({}),
        default_secret_ttl_seconds=10,
        time_provider=clock.now,
    )

    first = resolver.get_secret(secret_path)
    second = resolver.get_secret(secret_path)
    assert first == "v1"
    assert second == "v1"
    assert fetcher.calls == 1

    fetcher.values[secret_path] = "v2"
    resolver.invalidate(secret_path)
    rotated = resolver.get_secret(secret_path)
    assert rotated == "v2"
    assert fetcher.calls == 2

    clock.current += 11
    expired = resolver.get_secret(secret_path)
    assert expired == "v2"
    assert fetcher.calls == 3


def test_jwks_cache_uses_ttl() -> None:
    clock = _MutableClock()
    jwks_url = "https://issuer.example/keys"
    jwks_fetcher = _CountingJwksFetcher({jwks_url: {"keys": [{"kid": "1"}]}})
    resolver = CachedSecretResolver(
        secret_fetcher=_CountingSecretFetcher({}),
        jwks_fetcher=jwks_fetcher,
        default_jwks_ttl_seconds=30,
        time_provider=clock.now,
    )

    payload_1 = resolver.get_jwks(jwks_url)
    payload_2 = resolver.get_jwks(jwks_url)
    assert payload_1 == payload_2
    assert jwks_fetcher.calls == 1

    clock.current += 31
    payload_3 = resolver.get_jwks(jwks_url)
    assert payload_3 == payload_1
    assert jwks_fetcher.calls == 2


@pytest.mark.asyncio
async def test_registry_fails_closed_for_unknown_provider_channel() -> None:
    registry = AuthValidatorRegistry()
    request = AuthValidationRequest(tenant_id="t-1", provider="unknown", channel="webhook")

    result = await registry.validate(request)
    assert result.authenticated is False
    assert result.reason == "unknown_validator"


@pytest.mark.asyncio
async def test_default_registry_contains_expected_validators() -> None:
    secret_values = {
        "/secamo/tenants/t-1/webhooks/crowdstrike_secret": "crowd-secret",
        "/secamo/tenants/t-1/chatops/slack_signing_secret": "slack-secret",
    }
    resolver = CachedSecretResolver(
        secret_fetcher=_CountingSecretFetcher(secret_values),
        jwks_fetcher=_CountingJwksFetcher({}),
    )
    registry = build_default_validator_registry(resolver)

    body = "{}"
    crowd_signature = hmac.new(
        b"crowd-secret",
        body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    crowd_request = AuthValidationRequest(
        tenant_id="t-1",
        provider="crowdstrike",
        channel="webhook",
        headers={"x-cs-signature": crowd_signature},
        raw_body=body,
    )
    crowd_result = await registry.validate(crowd_request)
    assert crowd_result.authenticated is True
