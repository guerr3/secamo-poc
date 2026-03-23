"""Public normalization contracts for intent emission.

Responsibility: define WorkflowIntent as the only public output from normalization.
This module must not include provider-specific parsing logic or internal canonical wrappers.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shared.approval.contracts import SignalPayload


class WorkflowIntent(BaseModel):
    """Public intent contract emitted by normalization for ingress dispatching."""

    # frozen: Temporal activity input — must be immutable to guarantee deterministic replay
    model_config = ConfigDict(frozen=True)

    tenant_id: str
    provider: str
    event_type: str
    intent_type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    signal: SignalPayload | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
