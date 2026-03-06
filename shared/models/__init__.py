"""
shared.models — Secamo model package.

Re-exports every public symbol so existing imports like
``from shared.models import LifecycleRequest`` keep working.
"""

# ── Common enums ──────────────────────────────────────────────
from shared.models.common import LifecycleAction

# ── Domain contracts (Temporal workflows) ─────────────────────
from shared.models.domain import (
    AlertData,
    ApprovalDecision,
    DefenderAlertRequest,
    EnrichedAlert,
    EvidenceBundle,
    GraphUser,
    ImpossibleTravelRequest,
    LifecycleRequest,
    NotificationResult,
    RiskScore,
    TenantSecrets,
    TicketData,
    TicketResult,
    ThreatIntelResult,
    UserData,
)

# ── Ingress transport models ─────────────────────────────────
from shared.models.ingress import IamIngressRequest, RawIngressEnvelope

# ── Provider event models ────────────────────────────────────
from shared.models.provider_events import (
    DefenderWebhook,
    JiraIssueWebhook,
    ProviderEvent,
    TeamsApprovalCallback,
)

# ── Canonical event ──────────────────────────────────────────
from shared.models.canonical import CanonicalEvent

# ── Workflow commands ────────────────────────────────────────
from shared.models.commands import (
    SignalWorkflowCommand,
    StartWorkflowCommand,
    WorkflowCommand,
)

# ── Mappers ──────────────────────────────────────────────────
from shared.models.mappers import (
    build_provider_event,
    iam_request_to_canonical,
    to_approval_decision,
    to_canonical_event,
    to_defender_alert_request,
    to_lifecycle_request,
    to_workflow_command,
)

__all__ = [
    # common
    "LifecycleAction",
    # domain
    "AlertData",
    "ApprovalDecision",
    "DefenderAlertRequest",
    "EnrichedAlert",
    "EvidenceBundle",
    "GraphUser",
    "ImpossibleTravelRequest",
    "LifecycleRequest",
    "NotificationResult",
    "RiskScore",
    "TenantSecrets",
    "TicketData",
    "TicketResult",
    "ThreatIntelResult",
    "UserData",
    # ingress
    "IamIngressRequest",
    "RawIngressEnvelope",
    # provider events
    "DefenderWebhook",
    "JiraIssueWebhook",
    "ProviderEvent",
    "TeamsApprovalCallback",
    # canonical
    "CanonicalEvent",
    # commands
    "SignalWorkflowCommand",
    "StartWorkflowCommand",
    "WorkflowCommand",
    # mappers
    "build_provider_event",
    "iam_request_to_canonical",
    "to_approval_decision",
    "to_canonical_event",
    "to_defender_alert_request",
    "to_lifecycle_request",
    "to_workflow_command",
]
