"""
shared.models.ingress — Ingress transport models.

RawIngressEnvelope:  represents the raw inbound request entering the
                     ingress Lambda (before provider-specific parsing).

IamIngressRequest:   first-party API request model for the IAM ingress
                     endpoint.  NOT a ProviderEvent — IAM requests come
                     from our own API, not from an external vendor webhook.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class RawIngressEnvelope(BaseModel):
    """Raw representation of an inbound ingress request."""
    model_config = ConfigDict(extra="ignore")

    request_id: str
    tenant_id: str
    provider: str
    route: str
    method: str
    headers: dict[str, str]
    query_params: dict[str, str] = Field(default_factory=dict)
    path_params: dict[str, str] = Field(default_factory=dict)
    signature_valid: Optional[bool] = None
    signature_details: Optional[dict[str, Any]] = None
    received_at: datetime
    raw_body: dict[str, Any] | list[Any] | str | None = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None


class IamIngressRequest(BaseModel):
    """
    First-party ingress request for the IAM onboarding endpoint.

    This is a standalone ingress model — not a ProviderEvent subclass —
    because IAM requests originate from our own API, not external vendors.
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
