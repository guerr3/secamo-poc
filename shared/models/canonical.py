"""
shared.models.canonical — Normalized internal event representation.

The CanonicalEvent is the provider-agnostic event model that sits
between provider-specific parsing and workflow command generation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from shared.models.common import LifecycleAction


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


class AlertData(BaseModel):
    """Raw alert payload normalized for workflow processing."""

    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    severity: str
    title: str
    description: str
    device_id: Optional[str] = None
    user_email: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None


class UserContext(BaseModel):
    """User identity context with optional IAM intent payload."""

    model_config = ConfigDict(extra="ignore")

    user_id: Optional[str] = None
    user_principal_name: Optional[str] = None
    display_name: Optional[str] = None
    action: Optional[LifecycleAction] = None
    user_data: Optional[dict[str, Any]] = None


class DeviceContext(BaseModel):
    """Device identity and posture context."""

    model_config = ConfigDict(extra="ignore")

    device_id: Optional[str] = None
    device_name: Optional[str] = None
    risk_score: Optional[str] = None
    compliance_state: Optional[str] = None


class NetworkContext(BaseModel):
    """Network source and destination context."""

    model_config = ConfigDict(extra="ignore")

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    location: Optional[str] = None


class SecurityEvent(BaseModel):
    """Universal workflow input contract across all ingress providers."""

    model_config = ConfigDict(extra="ignore")

    event_id: str
    tenant_id: str
    event_type: str
    source_provider: str
    requester: str
    severity: Optional[str] = None
    correlation_id: Optional[str] = None
    ticket_id: Optional[str] = None

    alert: AlertData | None = None
    user: UserContext | None = None
    device: DeviceContext | None = None
    network: NetworkContext | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)
