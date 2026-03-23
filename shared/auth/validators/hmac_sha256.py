"""Configurable HMAC-SHA256 validator for webhook signature authentication.

Responsibility: perform signature verification for providers using shared HMAC semantics.
This module must not contain route-selection logic or Temporal SDK dependencies.
"""

from __future__ import annotations

import hashlib
import hmac

from shared.auth.contracts import AuthValidationRequest, AuthValidationResult, SecretResolver


class HmacSha256Validator:
    """Validate webhook signature headers using tenant-specific shared secrets."""

    def __init__(
        self,
        resolver: SecretResolver,
        *,
        validator_name: str,
        secret_relative_path: str,
        signature_header_name: str,
        signature_prefix: str | None = None,
    ) -> None:
        self._resolver = resolver
        self._validator_name = validator_name
        self._secret_relative_path = secret_relative_path
        self._signature_header_name = signature_header_name.lower()
        self._signature_prefix = signature_prefix

    @staticmethod
    def _find_header(headers: dict[str, str], name: str) -> str:
        wanted = name.lower()
        for header_name, value in headers.items():
            if str(header_name).lower() == wanted:
                return str(value)
        return ""

    def _normalize_supplied_signature(self, supplied: str) -> str:
        normalized = supplied.strip()
        if self._signature_prefix and normalized.lower().startswith(self._signature_prefix.lower()):
            return normalized[len(self._signature_prefix) :]
        return normalized

    async def validate(self, request: AuthValidationRequest) -> AuthValidationResult:
        signature = self._find_header(request.headers, self._signature_header_name)
        if not signature:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="missing_signature_header",
            )

        secret = self._resolver.get_tenant_secret(request.tenant_id, self._secret_relative_path)
        if not secret:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="missing_shared_secret",
            )

        expected = hmac.new(
            secret.encode("utf-8"),
            request.raw_body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        supplied = self._normalize_supplied_signature(signature)

        if not hmac.compare_digest(supplied, expected):
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="signature_mismatch",
            )

        return AuthValidationResult(
            authenticated=True,
            validator_name=self._validator_name,
        )
