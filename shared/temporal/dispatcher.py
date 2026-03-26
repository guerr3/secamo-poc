"""Ingress fan-out dispatcher abstractions for workflow start operations.

Responsibility: bridge Envelope and WorkflowRoute dispatch using a transport-agnostic workflow starter.
This module must not parse provider payloads or contain endpoint handler logic.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from shared.models.canonical import Envelope
from shared.routing.contracts import DispatchReport, WorkflowRoute
from shared.routing.registry import RouteDispatcher, RouteRegistry


@runtime_checkable
class WorkflowStarter(Protocol):
    """Protocol for starting workflows from routed ingress envelopes."""

    async def start(
        self,
        *,
        workflow_name: str,
        workflow_input: dict[str, Any],
        task_queue: str,
        tenant_id: str,
        workflow_id: str,
    ) -> Any:
        """Start one workflow execution for the provided route and input payload."""


class _WorkflowRouteDispatcher(RouteDispatcher):
    """Route dispatcher adapter that delegates route starts to WorkflowStarter."""

    def __init__(self, starter: WorkflowStarter) -> None:
        self._starter = starter

    async def dispatch(self, route: WorkflowRoute, envelope: Envelope) -> None:
        workflow_input = envelope.model_dump(mode="json")
        workflow_id = (
            f"ingress-{envelope.tenant_id}-{route.workflow_name}-{envelope.payload.event_type}-{envelope.event_id}"
        )
        await self._starter.start(
            workflow_name=route.workflow_name,
            workflow_input=workflow_input,
            task_queue=route.task_queue,
            tenant_id=envelope.tenant_id,
            workflow_id=workflow_id,
        )


class RouteFanoutDispatcher:
    """Best-effort fan-out dispatcher using shared route registry semantics."""

    def __init__(self, route_registry: RouteRegistry, workflow_starter: WorkflowStarter) -> None:
        self._route_registry = route_registry
        self._dispatcher = _WorkflowRouteDispatcher(workflow_starter)

    async def dispatch_intent(self, envelope: Envelope) -> DispatchReport:
        """Dispatch one Envelope across all matching WorkflowRoute entries."""

        return await self._route_registry.dispatch_best_effort(envelope, self._dispatcher)
