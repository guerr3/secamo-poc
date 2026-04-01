"""Code-defined route registry with best-effort fan-out dispatch behavior.

Responsibility: resolve list[WorkflowRoute] targets and dispatch all routes without fail-fast blocking.
This module must not contain provider payload parsing or workflow business logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Protocol, runtime_checkable

from shared.models.canonical import Envelope
from shared.routing.contracts import DispatchReport, RouteFailure, WorkflowRoute


@runtime_checkable
class RouteDispatcher(Protocol):
    """Dispatch protocol used by route registry fan-out execution."""

    async def dispatch(self, route: WorkflowRoute, envelope: Envelope) -> None:
        """Dispatch one workflow route for an envelope."""


class UnroutableEventError(RuntimeError):
    """Raised when no routing rule or fallback route matches an envelope."""


RoutePredicate = Callable[[Envelope], bool]


@dataclass(frozen=True)
class _RouteRule:
    """Internal explicit route rule evaluated before fallback resolution."""

    name: str
    predicate: RoutePredicate
    routes: tuple[WorkflowRoute, ...]


class RouteRegistry:
    """In-memory route registry with explicit rule priority and event fallback."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._fallback_routes: dict[tuple[str, str], tuple[WorkflowRoute, ...]] = {}
        self._polling_resource_event_types: dict[tuple[str, str], str] = {}
        self._webhook_resource_event_types: dict[tuple[str, str], str] = {}
        self._rules: list[_RouteRule] = []
        self._logger = logger or logging.getLogger("routing.registry")

    @staticmethod
    def _route_key(provider: str, event_type: str) -> tuple[str, str]:
        return provider.strip().lower(), event_type.strip().lower()

    @staticmethod
    def _resource_key(provider: str, resource_type: str) -> tuple[str, str]:
        return provider.strip().lower(), resource_type.strip().lower()

    @staticmethod
    def _normalize_webhook_resource(resource_type: str) -> str:
        resource_key = resource_type.strip().lower().lstrip("/")
        if resource_key.count("/") >= 2:
            # Microsoft Graph often sends resources like security/alerts_v2/{id}.
            resource_key = resource_key.rsplit("/", 1)[0]
        return resource_key

    def register(self, provider: str, event_type: str, routes: tuple[WorkflowRoute, ...]) -> None:
        """Register fallback routes for a provider + event-type pair."""

        self._fallback_routes[self._route_key(provider, event_type)] = routes

    def register_polling_resource(self, provider: str, resource_type: str, event_type: str) -> None:
        """Register provider polling resource mapping to a provider event type."""

        self._polling_resource_event_types[self._resource_key(provider, resource_type)] = event_type.strip().lower()

    def register_webhook_resource(self, provider: str, resource_type: str, event_type: str) -> None:
        """Register webhook resource mapping to a canonical/provider event type."""

        normalized_resource = self._normalize_webhook_resource(resource_type)
        self._webhook_resource_event_types[self._resource_key(provider, normalized_resource)] = event_type.strip().lower()

    def register_rule(self, name: str, predicate: RoutePredicate, routes: tuple[WorkflowRoute, ...]) -> None:
        """Register an explicit expression rule evaluated before fallback routes."""

        self._rules.append(_RouteRule(name=name, predicate=predicate, routes=routes))

    def iter_registered_routes(self) -> tuple[WorkflowRoute, ...]:
        """Return all registered routes (fallback and rule routes) for validation use cases."""

        routes: list[WorkflowRoute] = []
        for route_group in self._fallback_routes.values():
            routes.extend(route_group)
        for rule in self._rules:
            routes.extend(rule.routes)
        return tuple(routes)

    def resolve_provider_event(self, provider: str, event_type: str) -> tuple[WorkflowRoute, ...]:
        """Resolve fallback routes directly from provider + event-type keys."""

        return self._fallback_routes.get(self._route_key(provider, event_type), ())

    @staticmethod
    def _resolve_event_type_from_payload(payload: Any | None, default_event_type: str) -> str:
        if isinstance(payload, dict) and payload.get("provider_event_type"):
            return str(payload["provider_event_type"]).strip().lower()

        payload_event_type = getattr(payload, "event_type", None)
        if payload_event_type:
            return str(payload_event_type).strip().lower()

        return default_event_type

    def resolve_polling(self, provider: str, resource_type: str, payload: Any | None = None) -> tuple[WorkflowRoute, ...]:
        """Resolve provider routes from polling resource mappings."""

        default_event_type = self._polling_resource_event_types.get(self._resource_key(provider, resource_type))
        if default_event_type is None:
            return ()

        resolved_event_type = self._resolve_event_type_from_payload(payload, default_event_type)
        resolved_routes = self.resolve_provider_event(provider, resolved_event_type)
        if resolved_routes:
            return resolved_routes

        # Fall back to the configured resource mapping when payload hints are absent or unknown.
        return self.resolve_provider_event(provider, default_event_type)

    def resolve_webhook(self, provider: str, resource_type: str, payload: dict[str, Any] | None = None) -> tuple[WorkflowRoute, ...]:
        """Resolve provider routes from webhook resource mappings."""

        normalized_resource = self._normalize_webhook_resource(resource_type)
        mapped_event_type = self._webhook_resource_event_types.get(self._resource_key(provider, normalized_resource))
        if mapped_event_type:
            mapped_routes = self.resolve_provider_event(provider, mapped_event_type)
            if mapped_routes:
                return mapped_routes

        payload_event_type = None
        if payload and payload.get("provider_event_type"):
            payload_event_type = str(payload["provider_event_type"]).strip().lower()
        if payload_event_type:
            return self.resolve_provider_event(provider, payload_event_type)

        return ()

    def resolve(self, envelope: Envelope) -> tuple[WorkflowRoute, ...]:
        """Resolve routes using explicit rules first, then event-type fallback."""

        matched_routes: list[WorkflowRoute] = []
        for rule in self._rules:
            try:
                if rule.predicate(envelope):
                    matched_routes.extend(rule.routes)
            except Exception as exc:
                raise ValueError(f"route_rule_evaluation_failed:{rule.name}:{exc}") from exc

        if matched_routes:
            return tuple(matched_routes)

        fallback = self._fallback_routes.get(
            self._route_key(envelope.source_provider, envelope.payload.event_type),
            (),
        )
        if fallback:
            return fallback

        raise UnroutableEventError(
            (
                f"no_route_for_provider_event:{envelope.source_provider}:{envelope.payload.event_type} "
                f"tenant={envelope.tenant_id}"
            )
        )

    async def dispatch_best_effort(self, envelope: Envelope, dispatcher: RouteDispatcher) -> DispatchReport:
        """Dispatch all configured routes, continuing when individual routes fail."""

        routes = self.resolve(envelope)
        failures: list[RouteFailure] = []
        succeeded = 0

        for route in routes:
            try:
                await dispatcher.dispatch(route, envelope)
                succeeded += 1
            except Exception as exc:
                failure = RouteFailure(
                    workflow_name=route.workflow_name,
                    tenant_id=envelope.tenant_id,
                    provider=envelope.source_provider,
                    event_type=envelope.payload.event_type,
                    error=str(exc),
                )
                failures.append(failure)
                self._logger.exception(
                    "[fan-out error] workflow=%s tenant=%s reason=%s provider=%s event_type=%s",
                    route.workflow_name,
                    envelope.tenant_id,
                    str(exc),
                    envelope.source_provider,
                    envelope.payload.event_type,
                )

        return DispatchReport(
            attempted=len(routes),
            succeeded=succeeded,
            failed=len(failures),
            failures=tuple(failures),
        )
