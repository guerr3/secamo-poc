"""
shared.models.ingress — Ingress transport models.

IamIngressRequest:   first-party API request model for the IAM ingress
                     endpoint. IAM requests come
                     from our own API, not from an external vendor webhook.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class IamIngressRequest(BaseModel):
    """
    First-party ingress request for the IAM onboarding endpoint.

    This is a standalone ingress model because IAM requests originate from
    our own API, not external vendors.
    """
    model_config = ConfigDict(extra="ignore")

    action: str
    user_data: dict[str, Any]
    requester: str
    ticket_id: Optional[str] = None


class GraphNotificationItem(BaseModel):
    """Single change notification item delivered by Microsoft Graph."""
    model_config = ConfigDict(extra="ignore")

    subscriptionId: str
    changeType: str
    resource: str
    tenantId: Optional[str] = None
    clientState: Optional[str] = None
    subscriptionExpirationDateTime: Optional[datetime] = None
    resourceData: Optional[dict[str, Any]] = None


class GraphNotificationEnvelope(BaseModel):
    """Graph webhook payload with one or more change notification items."""
    model_config = ConfigDict(extra="ignore")

    value: list[GraphNotificationItem] = Field(default_factory=list)
    validationTokens: list[str] | None = None
