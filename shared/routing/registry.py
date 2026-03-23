"""Code-defined route registry with best-effort fan-out dispatch behavior.

Responsibility: resolve list[WorkflowRoute] targets and dispatch all routes without fail-fast blocking.
This module must not contain provider payload parsing or workflow business logic.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from shared.normalization.contracts import WorkflowIntent
from shared.routing.contracts import DispatchReport, RouteFailure, WorkflowRoute


@runtime_checkable
class RouteDispatcher(Protocol):
    """Dispatch protocol used by route registry fan-out execution."""

    async def dispatch(self, route: WorkflowRoute, intent: WorkflowIntent) -> None:
        """Dispatch one workflow route for a workflow intent."""


class RouteRegistry:
    """In-memory route registry keyed by provider/event_type."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._routes: dict[tuple[str, str], tuple[WorkflowRoute, ...]] = {}
        self._logger = logger or logging.getLogger("routing.registry")

    @staticmethod
    def _key(provider: str, event_type: str) -> tuple[str, str]:
        return provider.strip().lower(), event_type.strip().lower()

    def register(self, provider: str, event_type: str, routes: tuple[WorkflowRoute, ...]) -> None:
        """Register one or more workflow routes for a provider/event_type pair."""

        self._routes[self._key(provider, event_type)] = routes

    def resolve(self, provider: str, event_type: str) -> tuple[WorkflowRoute, ...]:
        """Resolve all workflow routes for the provider/event_type pair."""

        return self._routes.get(self._key(provider, event_type), ())

    async def dispatch_best_effort(self, intent: WorkflowIntent, dispatcher: RouteDispatcher) -> DispatchReport:
        """Dispatch all configured routes, continuing when individual routes fail."""

        routes = self.resolve(intent.provider, intent.event_type)
        failures: list[RouteFailure] = []
        succeeded = 0

        for route in routes:
            try:
                await dispatcher.dispatch(route, intent)
                succeeded += 1
            except Exception as exc:
                failure = RouteFailure(
                    workflow_name=route.workflow_name,
                    tenant_id=intent.tenant_id,
                    provider=intent.provider,
                    event_type=intent.event_type,
                    error=str(exc),
                )
                failures.append(failure)
                self._logger.exception(
                    "[fan-out error] workflow=%s tenant=%s reason=%s provider=%s event_type=%s",
                    route.workflow_name,
                    intent.tenant_id,
                    str(exc),
                    intent.provider,
                    intent.event_type,
                )

        return DispatchReport(
            attempted=len(routes),
            succeeded=succeeded,
            failed=len(failures),
            failures=tuple(failures),
        )
