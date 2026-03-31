"""
shared.models.domain — Temporal workflow domain contracts (Pydantic v2).

These models are the canonical inputs/outputs for Temporal workflows.
Migrated from dataclasses — field names and types are unchanged for
backwards compatibility.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from shared.models.canonical import DefenderDetectionFindingEvent, Envelope
from shared.models.subscriptions import SubscriptionConfig


class AITriageConfig(BaseModel):
    """Per-tenant configuration for AI triage provider selection and routing.

    Attributes:
        provider_type: Logical AI provider to instantiate via provider factory.
        credentials_path: SSM base path used to load provider credentials.
        default_channel: Optional default ChatOps target for triage outcomes.
        model_name: Optional model/deployment identifier for provider selection.
        temperature: Optional model temperature used for non-deterministic prompts.
        max_tokens: Optional response length cap for provider requests.
        enabled: Enables or disables AI triage for the tenant.
    """

    model_config = ConfigDict(from_attributes=True)

    provider_type: Literal["azure_openai", "aws_bedrock", "local"] = "azure_openai"
    credentials_path: str = "/secamo/tenants/{tenant_id}/ai_triage"
    default_channel: Optional[str] = None
    model_name: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 512
    enabled: bool = True


class ChatOpsConfig(BaseModel):
    """Per-tenant configuration for ChatOps provider selection and destinations.

    Attributes:
        provider_type: Logical ChatOps provider to instantiate via factory.
        credentials_path: SSM base path used to load provider credentials.
        default_channel: Default destination channel when a caller omits target.
        default_channels: Optional fan-out destinations for broadcast notifications.
        enabled: Enables or disables ChatOps notifications for the tenant.
    """

    model_config = ConfigDict(from_attributes=True)

    provider_type: Literal["ms_teams", "slack"] = "ms_teams"
    credentials_path: str = "/secamo/tenants/{tenant_id}/chatops"
    default_channel: Optional[str] = None
    default_channels: list[str] = Field(default_factory=list)
    enabled: bool = True


class TenantConfig(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    display_name: str = "Unknown Tenant"

    iam_provider: Literal["microsoft_graph", "okta", "entra_id", "custom"] = "microsoft_graph"
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
    ai_triage_config: AITriageConfig = Field(default_factory=AITriageConfig)
    chatops_config: ChatOpsConfig = Field(default_factory=ChatOpsConfig)
    polling_providers: list["PollingProviderConfig"] = Field(default_factory=list)
    graph_subscriptions: list[SubscriptionConfig] = Field(default_factory=list)


class PollingProviderConfig(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    provider: str
    resource_type: str
    secret_type: str = "graph"
    poll_interval_seconds: int = 300


class IdentityUser(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    identity_provider: str = "microsoft_graph"
    user_id: str
    email: str
    display_name: str
    account_enabled: bool


class DeviceContext(BaseModel):
    """Provider-agnostic device enrichment context used by SOC workflows."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    provider: str = "unknown"
    device_id: str
    display_name: str | None = None
    os_platform: str | None = None
    compliance_state: str | None = None
    risk_score: str | None = None


class IdentityRiskContext(BaseModel):
    """Provider-agnostic identity risk context used by SOC workflows."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    provider: str = "unknown"
    subject: str | None = None
    risk_level: str | None = None
    risk_state: str | None = None
    risk_detail: str | None = None


# ──────────────────────────────────────────────
# WF-02  Defender Alert Enrichment & Ticketing
# ──────────────────────────────────────────────


class EnrichedAlert(BaseModel):
    """Output of graph_enrich_alert — alert + extra Graph context."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

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
    model_config = ConfigDict(from_attributes=True, frozen=True)

    indicator: str
    is_malicious: bool
    provider: str
    reputation_score: float = 0.0
    details: str = ""


class RiskScore(BaseModel):
    """Calculated risk score for an alert."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    alert_id: str
    score: float              # 0.0 – 100.0
    level: str                # low | medium | high | critical
    factors: list[str] = Field(default_factory=list)


class TicketData(BaseModel):
    """Input for creating or updating a ticket."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    tenant_id: str
    title: str
    description: str
    severity: str
    source_workflow: str
    assignee: Optional[str] = None
    related_alert_id: Optional[str] = None


class TicketResult(BaseModel):
    """Result after ticket creation / update."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    ticket_id: str
    status: str
    url: str


class NotificationResult(BaseModel):
    """Result of a Teams or e-mail notification."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    success: bool
    channel: str              # "teams" | "email"
    message_id: Optional[str] = None


# ──────────────────────────────────────────────
# WF-05  Impossible Travel Alert Triage (HITL)
# ──────────────────────────────────────────────


class ConnectorFetchData(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    events: list[Envelope] = Field(default_factory=list)
    raw_count: int = 0


class ConnectorActionData(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    action: str
    payload: dict = Field(default_factory=dict)


class ConnectorHealthData(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    healthy: bool


class ConnectorFetchResult(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    operation_type: Literal["fetch"] = "fetch"
    provider: str
    success: bool = True
    details: str = "fetch completed"
    data: ConnectorFetchData


class ConnectorActionResult(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    operation_type: Literal["action"] = "action"
    provider: str
    success: bool
    details: str = ""
    data: ConnectorActionData


class ConnectorHealthResult(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True)

    operation_type: Literal["health"] = "health"
    provider: str
    success: bool
    details: str = ""
    data: ConnectorHealthData


class ApprovalDecision(BaseModel):
    """Signal payload for the HITL approval step in WF-05."""
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    approved: bool
    reviewer: str
    action: str              # "dismiss" | "isolate" | "disable_user"
    comments: str = ""


class HiTLRequest(BaseModel):
    """Generic workflow request contract for Human-in-the-Loop approvals."""
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    workflow_id: str
    run_id: str = ""
    tenant_id: str
    title: str
    description: str
    allowed_actions: list[str]
    reviewer_email: str
    ticket_key: Optional[str] = None
    channels: list[str] = Field(default_factory=lambda: ["email", "teams"])
    timeout_hours: int = 8
    metadata: dict = Field(default_factory=dict)


class HitlCallbackBinding(BaseModel):
    """Token and callback endpoint binding shared by all HITL channels."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    token: str
    callback_endpoint: str
    workflow_id: str
    run_id: str = ""
    allowed_actions: tuple[str, ...] = ()


class HitlChannelDispatchResult(BaseModel):
    """Per-channel outbound delivery result for HITL requests."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    channel: str
    success: bool
    message_id: str | None = None
    error_type: str | None = None
    error_message: str | None = None


class HitlDispatchResult(BaseModel):
    """Typed aggregate result returned by request_hitl_approval activity."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    workflow_id: str
    run_id: str = ""
    token_preview: str
    channel_results: list[HitlChannelDispatchResult] = Field(default_factory=list)
    any_channel_succeeded: bool
    failed_channels: list[str] = Field(default_factory=list)


class EvidenceBundle(BaseModel):
    """Collected evidence bundle for compliance/audit trail."""
    model_config = ConfigDict(from_attributes=True, frozen=True)

    workflow_id: str
    tenant_id: str
    alert_id: str
    items: list[dict] = Field(default_factory=list)
    bundle_url: str = ""


# ──────────────────────────────────────────────
# Child workflow contracts
# ──────────────────────────────────────────────

class ThreatIntelEnrichmentRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    indicator: str
    providers: list[str] = Field(default_factory=list)


class AlertEnrichmentRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    alert: DefenderDetectionFindingEvent
    edr_provider: str
    identity_provider: str | None = None
    threat_intel: ThreatIntelResult | None = None


class AlertEnrichmentResult(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    enriched_alert: EnrichedAlert
    risk_score: RiskScore


class TicketCreationRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    title: str
    description: str
    severity: str
    source_workflow: str
    ticketing_provider: str


class HiTLApprovalRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    hitl_request: HiTLRequest
    hitl_timeout_hours: int = 8
    auto_isolate_on_timeout: bool = False
    escalation_enabled: bool = True
    edr_provider: str
    ticketing_provider: str
    device_id: str | None = None


class IncidentResponseRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    decision: ApprovalDecision
    user: IdentityUser | None = None
    user_email: str
    device_id: str | None = None
    ticket_id: str
    evidence_bundle_enabled: bool = True
    edr_provider: str
    ticketing_provider: str
    parent_workflow_id: str
    alert_id: str
    threat_intel: ThreatIntelResult
    recent_alert_count: int = 0


class UserDeprovisioningRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    user_id: str
    user_email: str


class PollingManagerInput(BaseModel):
    model_config = ConfigDict(from_attributes=True, frozen=True, extra="forbid")

    tenant_id: str
    provider: str
    resource_type: str
    secret_type: str = "graph"
    poll_interval_seconds: int = 300
    cursor: str | None = None
    iteration: int = 0


