"""Subscription orchestration contracts.

These contracts represent subscription lifecycle data independent from any
single provider implementation.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SubscriptionConfig(BaseModel):
    """Declarative per-tenant subscription configuration."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    resource: str
    change_types: list[str] = Field(default_factory=lambda: ["created", "updated"])
    include_resource_data: bool = False
    expiration_hours: int = 24
    encryption_certificate: str | None = Field(default=None, repr=False)
    encryption_certificate_id: str | None = None
    lifecycle_notification_url: str | None = None


class SubscriptionState(BaseModel):
    """Persisted runtime state for one subscription."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    subscription_id: str
    tenant_id: str
    resource: str
    change_types: list[str] = Field(default_factory=list)
    expires_at: datetime
    notification_url: str
    client_state: str = Field(repr=False)


class SubscriptionManagerInput(BaseModel):
    """Input contract for long-running subscription reconciliation workflow."""

    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    notification_url: str
    secret_type: str = "graph"
    iteration: int = 0