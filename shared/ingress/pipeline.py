"""Shared ingress webhook pipeline implementation.

Responsibility: execute one orchestration path for webhook/internal ingress events
(auth -> normalization -> envelope build -> route fan-out dispatch).
This module must not contain transport handler wiring or callback-specific token persistence logic.
This module must not import transport frameworks such as Lambda event wrappers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shared.auth import AuthValidationRequest, AuthValidatorRegistry
from shared.ingress.envelope_builder import build_envelope
from shared.ingress.errors import IngressError, IngressErrorCode
from shared.ingress.graph import GraphNotificationHelper
from shared.ingress.normalization import normalize_event_body
from shared.models import GraphNotificationEnvelope
from shared.routing.registry import UnroutableEventError
from shared.temporal.dispatcher import RouteFanoutDispatcher


@dataclass(frozen=True)
class AuthResult:
    authenticated: bool
    principal: str | None = None
    reason: str | None = None
    details: dict[str, Any] | None = None


@dataclass(frozen=True)
class PipelineDispatchResult:
    accepted: bool
    status_code: int
    tenant_id: str
    provider: str
    event_type: str
    canonical_event_type: str | None = None
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    error_code: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class GraphDispatchResult:
    accepted: bool
    status_code: int
    tenant_id: str
    received: int = 0
    dispatched: int = 0
    ignored: int = 0
    error_code: str | None = None
    error_message: str | None = None


class IngressPipeline:
    """Unified ingress orchestration for non-HiTL routes."""

    def __init__(
        self,
        *,
        auth_registry: AuthValidatorRegistry,
        route_fanout_dispatcher: RouteFanoutDispatcher,
        graph_helper: GraphNotificationHelper,
    ) -> None:
        self._auth_registry = auth_registry
        self._route_fanout_dispatcher = route_fanout_dispatcher
        self._graph_helper = graph_helper

    @staticmethod
    def _error_result(
        *,
        tenant_id: str,
        provider: str,
        event_type: str,
        status_code: int,
        code: IngressErrorCode,
        message: str,
    ) -> PipelineDispatchResult:
        error = IngressError(code=code, message=message)
        return PipelineDispatchResult(
            accepted=False,
            status_code=status_code,
            tenant_id=tenant_id,
            provider=provider,
            event_type=event_type,
            error_code=error.code.value,
            error_message=error.message,
        )

    async def authenticate(
        self,
        *,
        tenant_id: str,
        provider: str,
        headers: dict[str, str],
        raw_body: str,
        channel: str = "webhook",
    ) -> AuthResult:
        validation = await self._auth_registry.validate(
            AuthValidationRequest(
                tenant_id=tenant_id,
                provider=provider,
                channel=channel,
                headers=headers,
                raw_body=raw_body,
            )
        )
        return AuthResult(
            authenticated=validation.authenticated,
            principal=validation.principal,
            reason=validation.reason,
            details=validation.details,
        )

    async def dispatch_provider_event(
        self,
        *,
        raw_body: dict[str, Any],
        provider: str,
        event_type: str,
        tenant_id: str,
        headers: dict[str, str] | None = None,
        raw_body_text: str = "",
        channel: str = "webhook",
        authenticate: bool = True,
    ) -> PipelineDispatchResult:
        if authenticate:
            auth_result = await self.authenticate(
                tenant_id=tenant_id,
                provider=provider,
                headers={str(k): str(v) for k, v in (headers or {}).items()},
                raw_body=raw_body_text,
                channel=channel,
            )
            if not auth_result.authenticated:
                return self._error_result(
                    tenant_id=tenant_id,
                    provider=provider,
                    event_type=event_type,
                    status_code=401,
                    code=IngressErrorCode.AUTHENTICATION,
                    message="Invalid provider signature",
                )

        try:
            normalized = normalize_event_body(
                provider=provider,
                event_type=event_type,
                tenant_id=tenant_id,
                raw_body=raw_body,
            )
            canonical_event_type = str(normalized.get("event_type") or event_type).strip().lower()
            envelope = build_envelope(
                raw_body=raw_body,
                normalized=normalized,
                provider=provider,
                tenant_id=tenant_id,
                event_type=canonical_event_type,
            )
        except Exception as exc:
            return self._error_result(
                tenant_id=tenant_id,
                provider=provider,
                event_type=event_type,
                status_code=400,
                code=IngressErrorCode.NORMALIZATION,
                message=f"Normalized ingress payload failed Envelope validation: {exc}",
            )

        try:
            fanout_report = await self._route_fanout_dispatcher.dispatch_intent(envelope)
        except UnroutableEventError:
            return self._error_result(
                tenant_id=tenant_id,
                provider=provider,
                event_type=canonical_event_type,
                status_code=400,
                code=IngressErrorCode.ROUTING,
                message=(
                    f"No workflow mapping found for provider='{provider}' event_type='{canonical_event_type}'"
                ),
            )

        return PipelineDispatchResult(
            accepted=True,
            status_code=202,
            tenant_id=tenant_id,
            provider=provider,
            event_type=event_type,
            canonical_event_type=canonical_event_type,
            attempted=fanout_report.attempted,
            succeeded=fanout_report.succeeded,
            failed=fanout_report.failed,
        )

    async def dispatch_graph_notifications(
        self,
        *,
        tenant_id: str,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
        raw_body_text: str = "",
    ) -> GraphDispatchResult:
        auth_result = await self.authenticate(
            tenant_id=tenant_id,
            provider="microsoft_graph",
            headers={str(k): str(v) for k, v in (headers or {}).items()},
            raw_body=raw_body_text,
            channel="webhook",
        )
        if not auth_result.authenticated:
            error = IngressError(code=IngressErrorCode.AUTHENTICATION, message="Invalid provider signature")
            return GraphDispatchResult(
                accepted=False,
                status_code=401,
                tenant_id=tenant_id,
                error_code=error.code.value,
                error_message=error.message,
            )

        try:
            envelope = GraphNotificationEnvelope.model_validate(body)
        except Exception as exc:
            error = IngressError(
                code=IngressErrorCode.VALIDATION,
                message=f"Invalid Graph notification payload: {exc}",
            )
            return GraphDispatchResult(
                accepted=False,
                status_code=400,
                tenant_id=tenant_id,
                error_code=error.code.value,
                error_message=error.message,
            )

        if not self._graph_helper.validate_graph_validation_tokens(envelope.validationTokens):
            error = IngressError(
                code=IngressErrorCode.AUTHENTICATION,
                message="Invalid Graph validation tokens",
            )
            return GraphDispatchResult(
                accepted=False,
                status_code=401,
                tenant_id=tenant_id,
                error_code=error.code.value,
                error_message=error.message,
            )

        dispatched = 0
        ignored = 0
        for item in envelope.value:
            if not self._graph_helper.graph_client_state_matches_tenant(item.clientState, tenant_id):
                ignored += 1
                continue

            event_type = self._graph_helper.graph_event_type_from_resource(item.resource)
            if not event_type:
                ignored += 1
                continue

            provider_payload = self._graph_helper.graph_item_to_provider_payload(item.model_dump(mode="json"), event_type)
            dispatch_result = await self.dispatch_provider_event(
                raw_body=provider_payload,
                provider="microsoft_graph",
                event_type=event_type,
                tenant_id=tenant_id,
                authenticate=False,
            )
            if not dispatch_result.accepted:
                return GraphDispatchResult(
                    accepted=False,
                    status_code=dispatch_result.status_code,
                    tenant_id=tenant_id,
                    received=len(envelope.value),
                    dispatched=dispatched,
                    ignored=ignored,
                    error_code=dispatch_result.error_code,
                    error_message=dispatch_result.error_message,
                )
            dispatched += 1

        return GraphDispatchResult(
            accepted=True,
            status_code=202,
            tenant_id=tenant_id,
            received=len(envelope.value),
            dispatched=dispatched,
            ignored=ignored,
        )
