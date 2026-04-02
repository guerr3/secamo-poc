"""Provider/channel validator registry with fail-closed behavior.

Responsibility: map provider/channel combinations to auth validators and execute validation.
This module must not contain routing decisions, workflow orchestration, or transport handlers.
"""

from __future__ import annotations

from shared.auth.contracts import AuthValidationRequest, AuthValidationResult, AuthValidator, SecretResolver
from shared.auth.validators import HmacSha256Validator, MicrosoftGraphJwtValidator, SlackSignatureValidator


class AuthValidatorRegistry:
    """In-memory validator registry keyed by provider and channel."""

    def __init__(self) -> None:
        self._validators: dict[tuple[str, str], AuthValidator] = {}

    @staticmethod
    def _key(provider: str, channel: str) -> tuple[str, str]:
        return provider.strip().lower(), channel.strip().lower()

    def register(self, provider: str, channel: str, validator: AuthValidator) -> None:
        """Register a validator implementation for one provider/channel pair."""

        self._validators[self._key(provider, channel)] = validator

    def resolve(self, provider: str, channel: str) -> AuthValidator | None:
        """Resolve a validator for provider/channel or None if missing."""

        return self._validators.get(self._key(provider, channel))

    async def validate(self, request: AuthValidationRequest) -> AuthValidationResult:
        """Fail closed for unknown provider/channel and run resolved validator otherwise."""

        validator = self.resolve(request.provider, request.channel)
        if validator is None:
            return AuthValidationResult(
                authenticated=False,
                validator_name="registry",
                reason="unknown_validator",
                details={"provider": request.provider, "channel": request.channel},
            )
        return await validator.validate(request)


def build_default_validator_registry(resolver: SecretResolver) -> AuthValidatorRegistry:
    """Build phase-2 default validator registry for supported providers/channels."""

    registry = AuthValidatorRegistry()
    graph_jwt_validator = MicrosoftGraphJwtValidator(
        resolver=resolver,
        validator_name="microsoft_graph_jwt",
    )

    registry.register(
        "microsoft_graph",
        "webhook",
        graph_jwt_validator,
    )
    registry.register(
        "microsoft_defender",
        "webhook",
        graph_jwt_validator,
    )
    registry.register(
        "defender",
        "webhook",
        graph_jwt_validator,
    )
    registry.register(
        "crowdstrike",
        "webhook",
        HmacSha256Validator(
            resolver=resolver,
            validator_name="hmac_crowdstrike",
            secret_relative_path="webhooks/crowdstrike_secret",
            signature_header_name="x-cs-signature",
            signature_prefix=None,
        ),
    )
    registry.register(
        "sentinelone",
        "webhook",
        HmacSha256Validator(
            resolver=resolver,
            validator_name="hmac_sentinelone",
            secret_relative_path="webhooks/sentinelone_secret",
            signature_header_name="x-sentinel-one-signature",
            signature_prefix=None,
        ),
    )
    registry.register(
        "jira",
        "webhook",
        HmacSha256Validator(
            resolver=resolver,
            validator_name="hmac_jira",
            secret_relative_path="webhooks/jira_secret",
            signature_header_name="x-hub-signature-256",
            signature_prefix="sha256=",
        ),
    )
    registry.register(
        "slack",
        "chatops",
        SlackSignatureValidator(resolver=resolver),
    )
    return registry
