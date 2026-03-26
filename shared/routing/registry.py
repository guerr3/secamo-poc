"""Code-defined route registry with best-effort fan-out dispatch behavior.

Responsibility: resolve list[WorkflowRoute] targets and dispatch all routes without fail-fast blocking.
This module must not contain provider payload parsing or workflow business logic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

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
        self._fallback_routes: dict[str, tuple[WorkflowRoute, ...]] = {}
        self._rules: list[_RouteRule] = []
        self._logger = logger or logging.getLogger("routing.registry")

    @staticmethod
    def _event_key(event_type: str) -> str:
        return event_type.strip().lower()

    def register(self, provider: str, event_type: str, routes: tuple[WorkflowRoute, ...]) -> None:
        """Register fallback routes for an event type.

        The provider argument is retained for API compatibility with existing callers,
        but fallback resolution is intentionally keyed by envelope payload event_type only.
        """

        _ = provider
        self._fallback_routes[self._event_key(event_type)] = routes

    def register_rule(self, name: str, predicate: RoutePredicate, routes: tuple[WorkflowRoute, ...]) -> None:
        """Register an explicit expression rule evaluated before fallback routes."""

        self._rules.append(_RouteRule(name=name, predicate=predicate, routes=routes))

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

        fallback = self._fallback_routes.get(self._event_key(envelope.payload.event_type), ())
        if fallback:
            return fallback

        raise UnroutableEventError(
            f"no_route_for_event_type:{envelope.payload.event_type} tenant={envelope.tenant_id}"
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
