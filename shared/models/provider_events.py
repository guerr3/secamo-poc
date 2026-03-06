"""
shared.models.provider_events — External vendor webhook models.

All provider event models use ``extra="ignore"`` so unknown fields
from external vendor payloads never cause validation errors.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class ProviderEvent(BaseModel):
    """Base class for external vendor webhook payloads."""
    model_config = ConfigDict(extra="ignore")

    provider: str
    event_name: str
    external_event_id: Optional[str] = None
    tenant_id: Optional[str] = None
    occurred_at: Optional[datetime] = None
    raw_payload: dict[str, Any] = {}


# ── Microsoft Defender ────────────────────────────────────────

class DefenderWebhook(ProviderEvent):
    """Parsed Defender / Sentinel alert webhook payload."""

    alert_id: str
    severity: str
    title: str
    description: Optional[str] = None
    device_id: Optional[str] = None
    user_email: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None


# ── Jira ──────────────────────────────────────────────────────

class JiraIssueWebhook(ProviderEvent):
    """Parsed Jira issue webhook payload."""

    issue_key: str
    issue_id: Optional[str] = None
    summary: Optional[str] = None
    status: Optional[str] = None
    reporter: Optional[str] = None
    assignee: Optional[str] = None


# ── Microsoft Teams ───────────────────────────────────────────

class TeamsApprovalCallback(ProviderEvent):
    """Parsed Teams adaptive card approval callback."""

    workflow_id: str
    approved: bool
    reviewer: str
    action: str
    comments: str = ""
