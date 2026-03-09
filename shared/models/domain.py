"""
shared.models.domain — Temporal workflow domain contracts (Pydantic v2).

These models are the canonical inputs/outputs for Temporal workflows.
Migrated from dataclasses — field names and types are unchanged for
backwards compatibility.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shared.models.common import LifecycleAction


# ──────────────────────────────────────────────
# WF-01  User Lifecycle Management
# ──────────────────────────────────────────────

class UserData(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: str
    first_name: str
    last_name: str
    department: str
    role: str
    manager_email: Optional[str] = None
    license_sku: Optional[str] = None


class LifecycleRequest(BaseModel):
    """Workflow input for WF-01 (IAM Onboarding)."""
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    action: LifecycleAction
    user_data: UserData
    requester: str
    ticket_id: str = ""

    @field_validator("action", mode="before")
    @classmethod
    def _coerce_action(cls, v):
        """Accept plain str or list-of-chars (legacy edge case)."""
        if isinstance(v, list):
            v = "".join(v)
        return LifecycleAction(v) if isinstance(v, str) else v


class TenantSecrets(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    client_id: str
    client_secret: str = Field(repr=False)
    tenant_azure_id: str


class GraphUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    email: str
    display_name: str
    account_enabled: bool


# ──────────────────────────────────────────────
# WF-02  Defender Alert Enrichment & Ticketing
# ──────────────────────────────────────────────

class AlertData(BaseModel):
    """Raw alert payload coming from Microsoft Defender / Sentinel."""
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    severity: str          # low | medium | high | critical
    title: str
    description: str
    device_id: Optional[str] = None
    user_email: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None


class DefenderAlertRequest(BaseModel):
    """Workflow input for WF-02 (Defender Alert Enrichment)."""
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    alert: AlertData
    requester: str


class EnrichedAlert(BaseModel):
    """Output of graph_enrich_alert — alert + extra Graph context."""
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    severity: str
    title: str
    description: str
    user_display_name: Optional[str] = None
    user_department: Optional[str] = None
    device_display_name: Optional[str] = None
    device_os: Optional[str] = None
    device_compliance: Optional[str] = None


class ThreatIntelResult(BaseModel):
    """Result of threat intelligence lookup for an IP or indicator."""
    model_config = ConfigDict(from_attributes=True)

    indicator: str
    is_malicious: bool
    provider: str
    reputation_score: float = 0.0
    details: str = ""


class RiskScore(BaseModel):
    """Calculated risk score for an alert."""
    model_config = ConfigDict(from_attributes=True)

    alert_id: str
    score: float              # 0.0 – 100.0
    level: str                # low | medium | high | critical
    factors: list[str] = Field(default_factory=list)


class TicketData(BaseModel):
    """Input for creating or updating a ticket."""
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    title: str
    description: str
    severity: str
    source_workflow: str
    assignee: Optional[str] = None
    related_alert_id: Optional[str] = None


class TicketResult(BaseModel):
    """Result after ticket creation / update."""
    model_config = ConfigDict(from_attributes=True)

    ticket_id: str
    status: str
    url: str


class NotificationResult(BaseModel):
    """Result of a Teams or e-mail notification."""
    model_config = ConfigDict(from_attributes=True)

    success: bool
    channel: str              # "teams" | "email"
    message_id: Optional[str] = None


# ──────────────────────────────────────────────
# WF-05  Impossible Travel Alert Triage (HITL)
# ──────────────────────────────────────────────

class ImpossibleTravelRequest(BaseModel):
    """Workflow input for WF-05 (Impossible Travel Alert Triage)."""
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    alert: AlertData
    user_email: str
    source_ip: str
    destination_ip: str
    requester: str


class ApprovalDecision(BaseModel):
    """Signal payload for the HITL approval step in WF-05."""
    model_config = ConfigDict(from_attributes=True)

    approved: bool
    reviewer: str
    action: str              # "dismiss" | "isolate" | "disable_user"
    comments: str = ""


class EvidenceBundle(BaseModel):
    """Collected evidence bundle for compliance/audit trail."""
    model_config = ConfigDict(from_attributes=True)

    workflow_id: str
    tenant_id: str
    alert_id: str
    items: list[dict] = Field(default_factory=list)
    bundle_url: str = ""
