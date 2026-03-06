"""
shared.models.canonical — Normalized internal event representation.

The CanonicalEvent is the provider-agnostic event model that sits
between provider-specific parsing and workflow command generation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class CanonicalEvent(BaseModel):
    """Provider-agnostic normalized event."""
    model_config = ConfigDict(extra="ignore")

    event_type: str
    tenant_id: str
    provider: str
    external_event_id: Optional[str] = None
    subject: Optional[str] = None
    actor: Optional[dict[str, Any]] = None
    resource: Optional[dict[str, Any]] = None
    severity: Optional[str] = None
    occurred_at: Optional[datetime] = None
    payload: dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
