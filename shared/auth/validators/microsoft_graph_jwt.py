"""Microsoft Graph JWT validator for signed webhook token verification.

Responsibility: verify bearer JWT claims and signature keys for tenant-scoped Microsoft issuers.
This module must not contain webhook routing logic or workflow execution behavior.
"""

from __future__ import annotations

import json
import os
from typing import Any

import jwt

from shared.auth.contracts import AuthValidationRequest, AuthValidationResult, SecretResolver


class MicrosoftGraphJwtValidator:
    """Validate Microsoft-signed bearer tokens against tenant issuer and audience."""

    def __init__(
        self,
        resolver: SecretResolver,
        *,
        validator_name: str = "microsoft_graph_jwt",
        tenant_id_relative_path: str = "graph/tenant_azure_id",
        audience: str | list[str] | None = None,
        jwks_ttl_seconds: int = 3600,
    ) -> None:
        self._resolver = resolver
        self._validator_name = validator_name
        self._tenant_id_relative_path = tenant_id_relative_path
        self._audience = audience if audience is not None else self._default_audience()
        self._jwks_ttl_seconds = jwks_ttl_seconds

    @staticmethod
    def _default_audience() -> str | list[str]:
        configured = [
            value.strip()
            for value in os.environ.get("GRAPH_NOTIFICATION_APP_IDS", "").split(",")
            if value.strip()
        ]
        if configured:
            return configured
        return "https://management.azure.com/"

    @staticmethod
    def _find_header(headers: dict[str, str], name: str) -> str:
        wanted = name.lower()
        for header_name, value in headers.items():
            if str(header_name).lower() == wanted:
                return str(value)
        return ""

    @staticmethod
    def _jwks_url(tenant_azure_id: str) -> str:
        return f"https://login.microsoftonline.com/{tenant_azure_id}/discovery/v2.0/keys"

    @staticmethod
    def _allowed_issuers(tenant_azure_id: str) -> set[str]:
        return {
            f"https://login.microsoftonline.com/{tenant_azure_id}/v2.0",
            f"https://sts.windows.net/{tenant_azure_id}/",
        }

    def _load_signing_key(self, token: str, jwks: dict[str, Any]) -> Any:
        header = jwt.get_unverified_header(token)
        kid = str(header.get("kid", ""))
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list) or not kid:
            raise ValueError("jwks_missing_key_set")

        for jwk in keys:
            if isinstance(jwk, dict) and str(jwk.get("kid", "")) == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        raise ValueError("matching_signing_key_not_found")

    def _decode_token(self, token: str, key: Any, tenant_azure_id: str) -> dict[str, Any]:
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=self._audience,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )

    async def validate(self, request: AuthValidationRequest) -> AuthValidationResult:
        auth_header = self._find_header(request.headers, "authorization")
        if not auth_header.lower().startswith("bearer "):
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="missing_bearer_token",
            )

        token = auth_header[7:].strip()
        if not token:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="empty_bearer_token",
            )

        tenant_azure_id = self._resolver.get_tenant_secret(request.tenant_id, self._tenant_id_relative_path)
        if not tenant_azure_id:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="missing_tenant_azure_id",
            )

        jwks = self._resolver.get_jwks(self._jwks_url(tenant_azure_id), ttl_seconds=self._jwks_ttl_seconds)
        if not jwks:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="jwks_unavailable",
            )

        try:
            key = self._load_signing_key(token, jwks)
            claims = self._decode_token(token, key, tenant_azure_id)
        except Exception:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="jwt_validation_failed",
            )

        issuer = str(claims.get("iss", ""))
        if issuer not in self._allowed_issuers(tenant_azure_id):
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="invalid_issuer",
            )

        principal = str(claims.get("sub") or claims.get("appid") or "")
        return AuthValidationResult(
            authenticated=True,
            validator_name=self._validator_name,
            principal=principal or None,
        )
