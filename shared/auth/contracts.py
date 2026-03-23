"""Protocol-based auth contracts for ingress validation.

Responsibility: define immutable request/result models and validator/resolver interfaces.
This module must not contain provider-specific validation logic or network calls.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class ResolverContext(BaseModel):
    """Context required to resolve tenant-scoped secret material."""

    model_config = ConfigDict()

    tenant_id: str
    provider: str
    channel: str = "webhook"


class AuthValidationRequest(BaseModel):
    """Immutable auth input consumed by validator implementations."""

    model_config = ConfigDict()

    tenant_id: str
    provider: str
    channel: str = "webhook"
    headers: dict[str, str] = Field(default_factory=dict)
    raw_body: str = ""


class AuthValidationResult(BaseModel):
    """Validator output with explicit pass/fail and optional reason metadata."""

    model_config = ConfigDict()

    authenticated: bool
    validator_name: str
    reason: str | None = None
    principal: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class SecretResolver(Protocol):
    """Resolver interface for secure parameter and JWKS retrieval."""

    def get_secret(self, full_path: str, ttl_seconds: int | None = None) -> str | None:
        """Return decrypted secret value for a fully-qualified parameter path."""

    def get_tenant_secret(self, tenant_id: str, relative_path: str, ttl_seconds: int | None = None) -> str | None:
        """Return decrypted secret value for a tenant-relative path."""

    def get_jwks(self, jwks_url: str, ttl_seconds: int | None = None) -> dict[str, Any] | None:
        """Return JWKS document payload for token verification."""


@runtime_checkable
class AuthValidator(Protocol):
    """Validator interface for provider/channel authentication verification."""

    async def validate(self, request: AuthValidationRequest) -> AuthValidationResult:
        """Validate authentication material and return immutable result metadata."""
