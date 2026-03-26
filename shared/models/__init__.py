"""shared.models package re-exports.

Exports current canonical/domain contracts used by workflows, ingress, and activities.
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
    HitlCallbackBinding,
    HitlChannelDispatchResult,
    HitlDispatchResult,
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
    Correlation,
    DefenderDetectionFindingEvent,
    DeviceContext,
    Envelope,
    HitlApprovalEvent,
    IamOnboardingEvent,
    ImpossibleTravelEvent,
    NetworkContext,
    SecurityEvent,
    StoragePartition,
    UserContext,
    VendorExtension,
    VendorExtensions,
    derive_event_id,
)

# ── Workflow commands ────────────────────────────────────────
from shared.models.commands import (
    SignalWorkflowCommand,
    StartWorkflowCommand,
    WorkflowCommand,
)


def _legacy_mapper_unavailable(*_args, **_kwargs):
    raise RuntimeError("legacy canonical mappers are not available with strict envelope models")


try:
    from shared.models.mappers import (
        build_provider_event,
        iam_request_to_canonical,
        resolve_webhook_route,
        to_approval_decision,
        to_canonical_event,
        to_security_event,
        to_workflow_command,
    )
except Exception:
    build_provider_event = _legacy_mapper_unavailable
    iam_request_to_canonical = _legacy_mapper_unavailable
    resolve_webhook_route = _legacy_mapper_unavailable
    to_approval_decision = _legacy_mapper_unavailable
    to_canonical_event = _legacy_mapper_unavailable
    to_security_event = _legacy_mapper_unavailable
    to_workflow_command = _legacy_mapper_unavailable

__all__ = [
    # common
    "LifecycleAction",
    # domain
    "AITriageConfig",
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
    "HitlCallbackBinding",
    "HitlChannelDispatchResult",
    "HitlDispatchResult",
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
    "Correlation",
    "DefenderDetectionFindingEvent",
    "DeviceContext",
    "Envelope",
    "HitlApprovalEvent",
    "IamOnboardingEvent",
    "ImpossibleTravelEvent",
    "NetworkContext",
    "SecurityEvent",
    "StoragePartition",
    "UserContext",
    "VendorExtension",
    "VendorExtensions",
    "derive_event_id",
    # commands
    "SignalWorkflowCommand",
    "StartWorkflowCommand",
    "WorkflowCommand",
    # legacy mapper symbols kept during transition
    "build_provider_event",
    "iam_request_to_canonical",
    "resolve_webhook_route",
    "to_approval_decision",
    "to_canonical_event",
    "to_security_event",
    "to_workflow_command",
]
