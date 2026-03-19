"""
shared.models.domain — Temporal workflow domain contracts (Pydantic v2).

These models are the canonical inputs/outputs for Temporal workflows.
Migrated from dataclasses — field names and types are unchanged for
backwards compatibility.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from shared.models.canonical import AlertData, CanonicalEvent


class TenantSecrets(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    client_id: str
    client_secret: str = Field(repr=False)
    tenant_azure_id: str
    teams_webhook_url: Optional[str] = Field(default=None, repr=False)
    jira_base_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = Field(default=None, repr=False)
    project_key: Optional[str] = None
    virustotal_api_key: Optional[str] = Field(default=None, repr=False)
    abuseipdb_api_key: Optional[str] = Field(default=None, repr=False)


class GraphSubscriptionConfig(BaseModel):
    """Declarative per-tenant Graph subscription configuration."""
    model_config = ConfigDict(from_attributes=True)

    resource: str
    change_types: list[str] = Field(default_factory=lambda: ["created", "updated"])
    include_resource_data: bool = False
    expiration_hours: int = 24


class GraphSubscriptionState(BaseModel):
    """Persisted runtime state for a Graph subscription."""
    model_config = ConfigDict(from_attributes=True)

    subscription_id: str
    tenant_id: str
    resource: str
    change_types: list[str] = Field(default_factory=list)
    expires_at: datetime
    notification_url: str
    client_state: str = Field(repr=False)


class TenantConfig(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    display_name: str = "Unknown Tenant"

    edr_provider: Literal["microsoft_defender", "crowdstrike", "sentinelone"] = "microsoft_defender"
    ticketing_provider: Literal["jira", "halo_itsm", "servicenow"] = "jira"
    threat_intel_providers: list[Literal["virustotal", "abuseipdb", "misp"]] = Field(default_factory=lambda: ["virustotal"])
    notification_provider: Literal["teams", "slack", "email"] = "teams"
    soc_analyst_email: Optional[str] = None

    sla_tier: Literal["platinum", "standard", "basic"] = "standard"
    hitl_timeout_hours: int = 4
    escalation_enabled: bool = True
    auto_isolate_on_timeout: bool = False
    max_activity_attempts: int = 3

    threat_intel_enabled: bool = True
    evidence_bundle_enabled: bool = True
    auto_ticket_creation: bool = True
    misp_sharing_enabled: bool = False
    polling_providers: list["PollingProviderConfig"] = Field(default_factory=list)
    graph_subscriptions: list[GraphSubscriptionConfig] = Field(default_factory=list)


class PollingProviderConfig(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    resource_type: str
    secret_type: str = "graph"
    poll_interval_seconds: int = 300


class GraphUser(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    email: str
    display_name: str
    account_enabled: bool


class DeviceDetail(BaseModel):
    """Defender for Endpoint machine entity fields from get-machine-by-id."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    computerDnsName: str | None = None
    firstSeen: str | None = None
    lastSeen: str | None = None
    osPlatform: str | None = None
    version: str | None = None
    osProcessor: str | None = None
    lastIpAddress: str | None = None
    lastExternalIpAddress: str | None = None
    osBuild: int | None = None
    healthStatus: str | None = None
    rbacGroupId: int | None = None
    rbacGroupName: str | None = None
    riskScore: str | None = None
    exposureLevel: str | None = None
    isAadJoined: bool | None = None
    aadDeviceId: str | None = None
    machineTags: list[str] = Field(default_factory=list)


class RiskyUserResult(BaseModel):
    """Identity Protection riskyUser resource fields from Graph v1.0."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    isDeleted: bool | None = None
    isProcessing: bool | None = None
    riskLastUpdatedDateTime: str | None = None
    riskLevel: str | None = None
    riskState: str | None = None
    riskDetail: str | None = None
    userDisplayName: str | None = None
    userPrincipalName: str | None = None


# ──────────────────────────────────────────────
# WF-02  Defender Alert Enrichment & Ticketing
# ──────────────────────────────────────────────


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


class ConnectorFetchResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    events: list[CanonicalEvent] = Field(default_factory=list)
    raw_count: int = 0


class ConnectorActionResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    action: str
    success: bool
    details: str = ""
    data: dict = Field(default_factory=dict)


class ConnectorHealthResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    healthy: bool
    details: str = ""


class ApprovalDecision(BaseModel):
    """Signal payload for the HITL approval step in WF-05."""
    model_config = ConfigDict(from_attributes=True)

    approved: bool
    reviewer: str
    action: str              # "dismiss" | "isolate" | "disable_user"
    comments: str = ""


class HiTLRequest(BaseModel):
    """Generic workflow request contract for Human-in-the-Loop approvals."""
    model_config = ConfigDict(from_attributes=True)

    workflow_id: str
    tenant_id: str
    title: str
    description: str
    allowed_actions: list[str]
    reviewer_email: str
    ticket_key: Optional[str] = None
    channels: list[str] = Field(default_factory=lambda: ["email", "jira"])
    timeout_hours: int = 8
    metadata: dict = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    """Collected evidence bundle for compliance/audit trail."""
    model_config = ConfigDict(from_attributes=True)

    workflow_id: str
    tenant_id: str
    alert_id: str
    items: list[dict] = Field(default_factory=list)
    bundle_url: str = ""


# ──────────────────────────────────────────────
# Child workflow contracts
# ──────────────────────────────────────────────

class ThreatIntelEnrichmentRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    indicator: str
    providers: list[str] = Field(default_factory=list)
    ti_secrets: TenantSecrets


class AlertEnrichmentRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    alert: AlertData
    edr_provider: str
    graph_secrets: TenantSecrets
    threat_intel: ThreatIntelResult | None = None


class AlertEnrichmentResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    enriched_alert: EnrichedAlert
    risk_score: RiskScore


class TicketCreationRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    title: str
    description: str
    severity: str
    source_workflow: str
    ticketing_provider: str
    ticketing_secrets: TenantSecrets


class HiTLApprovalRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    hitl_request: HiTLRequest
    config: TenantConfig
    graph_secrets: TenantSecrets
    ticketing_secrets: TenantSecrets
    edr_provider: str = "microsoft_defender"
    ticketing_provider: str = "jira"
    device_id: str | None = None


class IncidentResponseRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    decision: ApprovalDecision
    user: GraphUser | None = None
    user_email: str
    device_id: str | None = None
    ticket_id: str
    config: TenantConfig
    graph_secrets: TenantSecrets
    ticketing_secrets: TenantSecrets
    edr_provider: str = "microsoft_defender"
    ticketing_provider: str = "jira"
    parent_workflow_id: str
    alert_id: str
    threat_intel: ThreatIntelResult
    recent_alert_count: int = 0


class UserDeprovisioningRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    user_id: str
    user_email: str
    secrets: TenantSecrets


class PollingManagerInput(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    provider: str
    resource_type: str
    secret_type: str = "graph"
    poll_interval_seconds: int = 300
    cursor: str | None = None
    iteration: int = 0


class GraphSubscriptionManagerInput(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    notification_url: str
    secret_type: str = "graph"
    iteration: int = 0
