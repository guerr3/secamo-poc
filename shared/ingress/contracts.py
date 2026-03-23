"""Provider-agnostic ingress contracts for staged pipeline execution.

Responsibility: define immutable data contracts shared between ingress pipeline stages.
This module must not contain provider-specific rules, routing tables, or Temporal SDK imports.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IngressRequest(BaseModel):
    """Transport-neutral request shape consumed by ingress contracts."""

    model_config = ConfigDict()

    tenant_id: str
    provider: str
    event_type: str
    body: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    request_id: str | None = None


class IngressContext(BaseModel):
    """Execution metadata passed through every ingress pipeline stage."""

    model_config = ConfigDict()

    surface: str
    received_at: datetime
    trace_id: str | None = None


class AuthResult(BaseModel):
    """Authentication stage output used by downstream stages."""

    model_config = ConfigDict()

    authenticated: bool
    principal: str | None = None
    reason: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class IngressSignal(BaseModel):
    """Normalized signal emitted by normalization stage and consumed by routing."""

    model_config = ConfigDict()

    intent_name: str
    payload: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)


class DispatchItem(BaseModel):
    """Single dispatch candidate produced by routing stage."""

    model_config = ConfigDict()

    workflow_name: str
    task_queue: str
    signal: IngressSignal


class DispatchPlan(BaseModel):
    """Routing output representing all dispatch candidates for one request."""

    model_config = ConfigDict()

    provider: str
    event_type: str
    tenant_id: str
    items: tuple[DispatchItem, ...] = ()


class DispatchResult(BaseModel):
    """Dispatch stage status summary for a prepared route plan."""

    model_config = ConfigDict()

    dispatched_count: int = 0
    failed_count: int = 0
    errors: tuple[str, ...] = ()


class IngressOutcome(BaseModel):
    """Final contract returned by pipeline orchestration."""

    model_config = ConfigDict()

    accepted: bool
    status_code: int
    dispatch_result: DispatchResult | None = None
    error_code: str | None = None
    error_message: str | None = None
