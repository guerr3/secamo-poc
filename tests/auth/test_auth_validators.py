"""Phase-2 verification for concrete authentication validators.

Responsibility: validate positive and negative authentication vectors per validator implementation.
This module must not test routing behavior or workflow dispatch behavior.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from shared.auth.contracts import AuthValidationRequest
from shared.auth.secrets import CachedSecretResolver
from shared.auth.validators import HmacSha256Validator, MicrosoftGraphJwtValidator, SlackSignatureValidator


class _MapSecretFetcher:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def fetch_secret(self, full_path: str) -> str | None:
        return self.values.get(full_path)


class _MapJwksFetcher:
    def __init__(self, values: dict[str, dict]) -> None:
        self.values = values

    def fetch_jwks(self, jwks_url: str) -> dict | None:
        return self.values.get(jwks_url)


@pytest.mark.asyncio
async def test_hmac_validator_accepts_valid_signature() -> None:
    body = "{\"ok\":true}"
    secret = "topsecret"
    signature = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    resolver = CachedSecretResolver(
        secret_fetcher=_MapSecretFetcher({"/secamo/tenants/t-1/webhooks/jira_secret": secret}),
        jwks_fetcher=_MapJwksFetcher({}),
    )
    validator = HmacSha256Validator(
        resolver=resolver,
        validator_name="hmac_jira",
        secret_relative_path="webhooks/jira_secret",
        signature_header_name="x-hub-signature-256",
        signature_prefix="sha256=",
    )
    request = AuthValidationRequest(
        tenant_id="t-1",
        provider="jira",
        headers={"x-hub-signature-256": f"sha256={signature}"},
        raw_body=body,
    )

    result = await validator.validate(request)
    assert result.authenticated is True


@pytest.mark.asyncio
async def test_hmac_validator_rejects_mismatch() -> None:
    resolver = CachedSecretResolver(
        secret_fetcher=_MapSecretFetcher({"/secamo/tenants/t-1/webhooks/jira_secret": "secret"}),
        jwks_fetcher=_MapJwksFetcher({}),
    )
    validator = HmacSha256Validator(
        resolver=resolver,
        validator_name="hmac_jira",
        secret_relative_path="webhooks/jira_secret",
        signature_header_name="x-hub-signature-256",
        signature_prefix="sha256=",
    )
    request = AuthValidationRequest(
        tenant_id="t-1",
        provider="jira",
        headers={"x-hub-signature-256": "sha256=deadbeef"},
        raw_body="{}",
    )

    result = await validator.validate(request)
    assert result.authenticated is False
    assert result.reason == "signature_mismatch"


@pytest.mark.asyncio
async def test_slack_validator_accepts_valid_signature() -> None:
    body = "payload=hello"
    timestamp = 1_700_000_000
    secret = "slack-signing-secret"
    base = f"v0:{timestamp}:{body}".encode("utf-8")
    signature = "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()

    resolver = CachedSecretResolver(
        secret_fetcher=_MapSecretFetcher({"/secamo/tenants/t-1/chatops/slack_signing_secret": secret}),
        jwks_fetcher=_MapJwksFetcher({}),
    )
    validator = SlackSignatureValidator(resolver=resolver, time_provider=lambda: timestamp)
    request = AuthValidationRequest(
        tenant_id="t-1",
        provider="slack",
        channel="chatops",
        headers={
            "x-slack-request-timestamp": str(timestamp),
            "x-slack-signature": signature,
        },
        raw_body=body,
    )

    result = await validator.validate(request)
    assert result.authenticated is True


@pytest.mark.asyncio
async def test_slack_validator_rejects_stale_timestamp() -> None:
    resolver = CachedSecretResolver(
        secret_fetcher=_MapSecretFetcher({"/secamo/tenants/t-1/chatops/slack_signing_secret": "secret"}),
        jwks_fetcher=_MapJwksFetcher({}),
    )
    validator = SlackSignatureValidator(resolver=resolver, time_provider=lambda: 2_000)
    request = AuthValidationRequest(
        tenant_id="t-1",
        provider="slack",
        channel="chatops",
        headers={
            "x-slack-request-timestamp": "1000",
            "x-slack-signature": "v0=abc",
        },
        raw_body="payload=hello",
    )

    result = await validator.validate(request)
    assert result.authenticated is False
    assert result.reason == "stale_slack_timestamp"


@pytest.mark.asyncio
async def test_microsoft_graph_jwt_validator_accepts_valid_claims_with_injected_decode() -> None:
    tenant_azure_id = "tenant-azure-id"
    jwks_url = f"https://login.microsoftonline.com/{tenant_azure_id}/discovery/v2.0/keys"

    resolver = CachedSecretResolver(
        secret_fetcher=_MapSecretFetcher({"/secamo/tenants/t-1/graph/tenant_azure_id": tenant_azure_id}),
        jwks_fetcher=_MapJwksFetcher({jwks_url: {"keys": [{"kid": "kid-1"}]}}),
    )
    validator = MicrosoftGraphJwtValidator(resolver=resolver)

    validator._load_signing_key = lambda token, jwks: "signing-key"  # type: ignore[attr-defined]
    validator._decode_token = lambda token, key, tenant: {  # type: ignore[attr-defined]
        "iss": f"https://login.microsoftonline.com/{tenant}/v2.0",
        "sub": "principal-1",
    }

    request = AuthValidationRequest(
        tenant_id="t-1",
        provider="microsoft_defender",
        headers={"Authorization": "Bearer token-value"},
        raw_body="{}",
    )
    result = await validator.validate(request)
    assert result.authenticated is True
    assert result.principal == "principal-1"


@pytest.mark.asyncio
async def test_microsoft_graph_jwt_validator_rejects_invalid_issuer() -> None:
    tenant_azure_id = "tenant-azure-id"
    jwks_url = f"https://login.microsoftonline.com/{tenant_azure_id}/discovery/v2.0/keys"

    resolver = CachedSecretResolver(
        secret_fetcher=_MapSecretFetcher({"/secamo/tenants/t-1/graph/tenant_azure_id": tenant_azure_id}),
        jwks_fetcher=_MapJwksFetcher({jwks_url: {"keys": [{"kid": "kid-1"}]}}),
    )
    validator = MicrosoftGraphJwtValidator(resolver=resolver)

    validator._load_signing_key = lambda token, jwks: "signing-key"  # type: ignore[attr-defined]
    validator._decode_token = lambda token, key, tenant: {  # type: ignore[attr-defined]
        "iss": "https://invalid.example/issuer",
        "sub": "principal-1",
    }

    request = AuthValidationRequest(
        tenant_id="t-1",
        provider="microsoft_defender",
        headers={"Authorization": "Bearer token-value"},
        raw_body="{}",
    )
    result = await validator.validate(request)
    assert result.authenticated is False
    assert result.reason == "invalid_issuer"
