"""
shared.models — Secamo model package.

Re-exports every public symbol so existing imports like
``from shared.models import SecurityEvent`` keep working.
"""

# ── Common enums ──────────────────────────────────────────────
from shared.models.common import LifecycleAction

# ── Domain contracts (Temporal workflows) ─────────────────────
from shared.models.domain import (
    AITriageConfig,
    AlertEnrichmentRequest,
    AlertEnrichmentResult,
    ApprovalDecision,
    ChatOpsConfig,
    ConnectorActionResult,
    ConnectorFetchResult,
    ConnectorHealthResult,
    EnrichedAlert,
    EvidenceBundle,
    DeviceDetail,
    GraphSubscriptionManagerInput,
    GraphSubscriptionConfig,
    GraphSubscriptionState,
    GraphUser,
    HiTLApprovalRequest,
    HiTLRequest,
    IncidentResponseRequest,
    NotificationResult,
    PollingManagerInput,
    PollingProviderConfig,
    RiskyUserResult,
    RiskScore,
    TenantSecrets,
    TenantConfig,
    TicketData,
    TicketCreationRequest,
    TicketResult,
    ThreatIntelEnrichmentRequest,
    ThreatIntelResult,
    UserDeprovisioningRequest,
)

# ── AI triage and ChatOps contracts ─────────────────────────
from shared.models.chatops import ChatOpsAction, ChatOpsMessage, ChatOpsProvider
from shared.models.triage import AITriageProvider, TriageRequest, TriageResult

# ── Ingress transport models ─────────────────────────────────
from shared.models.ingress import IamIngressRequest, RawIngressEnvelope
from shared.models.ingress import GraphNotificationEnvelope, GraphNotificationItem

# ── Provider event models ────────────────────────────────────
from shared.models.provider_events import (
    DefenderWebhook,
    JiraIssueWebhook,
    ProviderEvent,
    TeamsApprovalCallback,
)

# ── Canonical event ──────────────────────────────────────────
from shared.models.canonical import (
    AlertData,
    CanonicalEvent,
    DeviceContext,
    NetworkContext,
    SecurityEvent,
    UserContext,
)

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
    resolve_webhook_route,
    to_approval_decision,
    to_canonical_event,
    to_security_event,
    to_workflow_command,
)

__all__ = [
    # common
    "LifecycleAction",
    # domain
    "AITriageConfig",
    "AlertData",
    "AlertEnrichmentRequest",
    "AlertEnrichmentResult",
    "ApprovalDecision",
    "ChatOpsConfig",
    "ChatOpsAction",
    "ChatOpsMessage",
    "ChatOpsProvider",
    "ConnectorActionResult",
    "ConnectorFetchResult",
    "ConnectorHealthResult",
    "DeviceDetail",
    "EnrichedAlert",
    "EvidenceBundle",
    "GraphNotificationEnvelope",
    "GraphNotificationItem",
    "GraphSubscriptionManagerInput",
    "GraphSubscriptionConfig",
    "GraphSubscriptionState",
    "GraphUser",
    "HiTLApprovalRequest",
    "HiTLRequest",
    "IncidentResponseRequest",
    "NotificationResult",
    "PollingManagerInput",
    "PollingProviderConfig",
    "RiskyUserResult",
    "RiskScore",
    "TenantSecrets",
    "TenantConfig",
    "TicketData",
    "TicketCreationRequest",
    "TicketResult",
    "ThreatIntelEnrichmentRequest",
    "ThreatIntelResult",
    "TriageRequest",
    "TriageResult",
    "AITriageProvider",
    "UserDeprovisioningRequest",
    # ingress
    "IamIngressRequest",
    "RawIngressEnvelope",
    # provider events
    "DefenderWebhook",
    "JiraIssueWebhook",
    "ProviderEvent",
    "TeamsApprovalCallback",
    # canonical
    "AlertData",
    "CanonicalEvent",
    "DeviceContext",
    "NetworkContext",
    "SecurityEvent",
    "UserContext",
    # commands
    "SignalWorkflowCommand",
    "StartWorkflowCommand",
    "WorkflowCommand",
    # mappers
    "build_provider_event",
    "iam_request_to_canonical",
    "resolve_webhook_route",
    "to_approval_decision",
    "to_canonical_event",
    "to_security_event",
    "to_workflow_command",
]
