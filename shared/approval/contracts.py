"""Typed approval signal contracts for ingress-to-workflow signaling.

Responsibility: define discriminated union payload models including the ApprovalSignal contract.
This module must not include channel-specific parsing logic or token persistence behavior.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApprovalSignal(BaseModel):
    """Core approval signal contract used by HITL callback channels."""

    # frozen: Temporal activity input — must be immutable to guarantee deterministic replay
    model_config = ConfigDict(frozen=True)

    signal_type: Literal["approval"] = "approval"
    approved: bool
    action: str = "approve"
    actor: str
    comments: str = ""


class GenericActionSignal(BaseModel):
    """Generic action signal contract for future non-approval signal actions."""

    model_config = ConfigDict()

    signal_type: Literal["generic_action"] = "generic_action"
    action: str
    actor: str
    payload: dict[str, Any] = Field(default_factory=dict)


SignalPayload = Annotated[ApprovalSignal | GenericActionSignal, Field(discriminator="signal_type")]
