

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ──────────────────────────────────────────────
# WF-01  User Lifecycle Management
# ──────────────────────────────────────────────

class LifecycleAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    PASSWORD_RESET = "password_reset"


@dataclass
class UserData:
    email: str
    first_name: str
    last_name: str
    department: str
    role: str
    manager_email: Optional[str] = None
    license_sku: Optional[str] = None


@dataclass
class LifecycleRequest:
    """Workflow input for WF-01 (IAM Onboarding)."""
    tenant_id: str
    action: LifecycleAction
    user_data: UserData
    requester: str
    ticket_id: str

    def __post_init__(self):
        if isinstance(self.action, list):
            self.action = LifecycleAction("".join(self.action))
        elif isinstance(self.action, str):
            self.action = LifecycleAction(self.action)
        if isinstance(self.user_data, dict):
            self.user_data = UserData(**self.user_data)


@dataclass
class TenantSecrets:
    client_id: str
    client_secret: str
    tenant_azure_id: str


@dataclass
class GraphUser:
    user_id: str
    email: str
    display_name: str
    account_enabled: bool


# ──────────────────────────────────────────────
# WF-02  Defender Alert Enrichment & Ticketing
# ──────────────────────────────────────────────

@dataclass
class AlertData:
    """Raw alert payload coming from Microsoft Defender / Sentinel."""
    alert_id: str
    severity: str          # low | medium | high | critical
    title: str
    description: str
    device_id: Optional[str] = None
    user_email: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None


@dataclass
class DefenderAlertRequest:
    """Workflow input for WF-02 (Defender Alert Enrichment)."""
    tenant_id: str
    alert: AlertData
    requester: str


@dataclass
class EnrichedAlert:
    """Output of graph_enrich_alert — alert + extra Graph context."""
    alert_id: str
    severity: str
    title: str
    description: str
    user_display_name: Optional[str] = None
    user_department: Optional[str] = None
    device_display_name: Optional[str] = None
    device_os: Optional[str] = None
    device_compliance: Optional[str] = None


@dataclass
class ThreatIntelResult:
    """Result of threat intelligence lookup for an IP or indicator."""
    indicator: str
    is_malicious: bool
    provider: str
    reputation_score: float = 0.0
    details: str = ""


@dataclass
class RiskScore:
    """Calculated risk score for an alert."""
    alert_id: str
    score: float              # 0.0 – 100.0
    level: str                # low | medium | high | critical
    factors: list[str] = field(default_factory=list)


@dataclass
class TicketData:
    """Input for creating or updating a ticket."""
    tenant_id: str
    title: str
    description: str
    severity: str
    source_workflow: str
    assignee: Optional[str] = None
    related_alert_id: Optional[str] = None


@dataclass
class TicketResult:
    """Result after ticket creation / update."""
    ticket_id: str
    status: str
    url: str


@dataclass
class NotificationResult:
    """Result of a Teams or e-mail notification."""
    success: bool
    channel: str              # "teams" | "email"
    message_id: Optional[str] = None


# ──────────────────────────────────────────────
# WF-05  Impossible Travel Alert Triage (HITL)
# ──────────────────────────────────────────────

@dataclass
class ImpossibleTravelRequest:
    """Workflow input for WF-05 (Impossible Travel Alert Triage)."""
    tenant_id: str
    alert: AlertData
    user_email: str
    source_ip: str
    destination_ip: str
    requester: str


@dataclass
class ApprovalDecision:
    """Signal payload for the HITL approval step in WF-05."""
    approved: bool
    reviewer: str
    action: str              # "dismiss" | "isolate" | "disable_user"
    comments: str = ""


@dataclass
class EvidenceBundle:
    """Collected evidence bundle for compliance/audit trail."""
    workflow_id: str
    tenant_id: str
    alert_id: str
    items: list[dict] = field(default_factory=list)
    bundle_url: str = ""
