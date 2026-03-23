"""Internal canonical event wrapper for normalization implementation details.

Responsibility: represent transient canonical shape used inside normalization internals only.
This module must not be consumed as a public contract by routing, ingress adapters, or workflow boundaries.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class InternalCanonicalEvent(BaseModel):
    """Internal normalization shape not intended for external module consumption."""

    model_config = ConfigDict()

    tenant_id: str
    provider: str
    event_type: str
    occurred_at: datetime | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
