"""Slack signature validator for chatops callback authentication.

Responsibility: verify Slack v0 signatures using tenant-scoped signing secrets.
This module must not contain provider routing logic or workflow dispatch behavior.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from shared.auth.contracts import AuthValidationRequest, AuthValidationResult, SecretResolver


class SlackSignatureValidator:
    """Validate Slack callback signatures with replay-window protection."""

    def __init__(
        self,
        resolver: SecretResolver,
        *,
        validator_name: str = "slack_signature",
        secret_relative_path: str = "chatops/slack_signing_secret",
        timestamp_header_name: str = "x-slack-request-timestamp",
        signature_header_name: str = "x-slack-signature",
        tolerance_seconds: int = 300,
        time_provider: callable | None = None,
    ) -> None:
        self._resolver = resolver
        self._validator_name = validator_name
        self._secret_relative_path = secret_relative_path
        self._timestamp_header_name = timestamp_header_name.lower()
        self._signature_header_name = signature_header_name.lower()
        self._tolerance_seconds = tolerance_seconds
        self._time = time_provider or time.time

    @staticmethod
    def _find_header(headers: dict[str, str], name: str) -> str:
        wanted = name.lower()
        for header_name, value in headers.items():
            if str(header_name).lower() == wanted:
                return str(value)
        return ""

    async def validate(self, request: AuthValidationRequest) -> AuthValidationResult:
        timestamp_raw = self._find_header(request.headers, self._timestamp_header_name)
        signature = self._find_header(request.headers, self._signature_header_name)
        if not timestamp_raw or not signature:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="missing_slack_signature_headers",
            )

        try:
            timestamp_value = int(timestamp_raw)
        except ValueError:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="invalid_slack_timestamp",
            )

        now_epoch = int(self._time())
        if abs(now_epoch - timestamp_value) > self._tolerance_seconds:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="stale_slack_timestamp",
            )

        secret = self._resolver.get_tenant_secret(request.tenant_id, self._secret_relative_path)
        if not secret:
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="missing_shared_secret",
            )

        base_string = f"v0:{timestamp_value}:{request.raw_body}".encode("utf-8")
        expected = "v0=" + hmac.new(secret.encode("utf-8"), base_string, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return AuthValidationResult(
                authenticated=False,
                validator_name=self._validator_name,
                reason="signature_mismatch",
            )

        return AuthValidationResult(authenticated=True, validator_name=self._validator_name)
