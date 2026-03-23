"""Routing contracts for multi-workflow ingress fan-out.

Responsibility: define immutable route and dispatch-report contracts for ingress dispatch planning.
This module must not contain provider-specific route selection rules or SDK dispatch calls.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class WorkflowRoute(BaseModel):
    """One workflow dispatch target for a provider/event route entry."""

    # frozen: Temporal activity input — must be immutable to guarantee deterministic replay
    model_config = ConfigDict(frozen=True)

    workflow_name: str
    task_queue: str


class RouteFailure(BaseModel):
    """One failed fan-out dispatch attempt with context fields."""

    model_config = ConfigDict()

    workflow_name: str
    tenant_id: str
    provider: str
    event_type: str
    error: str


class DispatchReport(BaseModel):
    """Best-effort fan-out dispatch result summary."""

    model_config = ConfigDict()

    attempted: int
    succeeded: int
    failed: int
    failures: tuple[RouteFailure, ...] = ()
