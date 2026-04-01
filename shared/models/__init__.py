"""shared.models package re-exports.

Exports current canonical/domain contracts used by workflows, ingress, and activities.
"""

# ── Common enums & constants ────────────────────────────────
from shared.models.common import HITL_APPROVAL_SIGNAL_NAME, LifecycleAction

# ── Domain contracts (Temporal workflows) ─────────────────────
from shared.models.domain import (
    AITriageConfig,
    AlertEnrichmentRequest,
    AlertEnrichmentResult,
    ApprovalDecision,
    ChatOpsConfig,
    ConnectorActionData,
    ConnectorActionResult,
    ConnectorFetchData,
    ConnectorFetchResult,
    ConnectorHealthData,
    ConnectorHealthResult,
    DeviceContext,
    EnrichedAlert,
    EvidenceBundle,
    IdentityUser,
    HitlCallbackBinding,
    HitlChannelDispatchResult,
    HitlDispatchResult,
    HiTLApprovalRequest,
    HiTLRequest,
    IncidentResponseRequest,
    IdentityRiskContext,
    NotificationResult,
    PollingManagerInput,
    PollingProviderConfig,
    RiskScore,
    TenantConfig,
    TicketData,
    TicketCreationRequest,
    TicketResult,
    ThreatIntelEnrichmentRequest,
    ThreatIntelResult,
    UserDeprovisioningRequest,
)
from shared.models.subscriptions import SubscriptionConfig, SubscriptionManagerInput, SubscriptionState

# ── AI triage and ChatOps contracts ─────────────────────────
from shared.models.chatops import ChatOpsAction, ChatOpsMessage
from shared.models.triage import TriageRequest, TriageResult
from shared.providers.protocols import AITriageProvider, ChatOpsProvider, IdentityAccessProvider, TicketingProvider

# ── Ingress transport models ─────────────────────────────────
from shared.models.ingress import IamIngressRequest
from shared.models.ingress import GraphNotificationEnvelope, GraphNotificationItem

# ── Canonical event ──────────────────────────────────────────
from shared.models.canonical import (
    Correlation,
    DefenderDetectionFindingEvent,
    Envelope,
    HitlApprovalEvent,
    IamOnboardingEvent,
    ImpossibleTravelEvent,
    StoragePartition,
    VendorExtension,
    VendorExtensions,
    derive_event_id,
)

# ── Canonical mappers ────────────────────────────────────────
from shared.models.mappers import (
    build_connector_correlation,
    build_envelope,
    build_storage_partition,
    to_approval_decision,
)

__all__ = [
    # common
    "HITL_APPROVAL_SIGNAL_NAME",
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
    "IdentityAccessProvider",
    "ConnectorActionData",
    "ConnectorActionResult",
    "ConnectorFetchData",
    "ConnectorFetchResult",
    "ConnectorHealthData",
    "ConnectorHealthResult",
    "DeviceContext",
    "EnrichedAlert",
    "EvidenceBundle",
    "IdentityUser",
    "IdentityRiskContext",
    "GraphNotificationEnvelope",
    "GraphNotificationItem",
    "SubscriptionManagerInput",
    "SubscriptionConfig",
    "SubscriptionState",
    "HitlCallbackBinding",
    "HitlChannelDispatchResult",
    "HitlDispatchResult",
    "HiTLApprovalRequest",
    "HiTLRequest",
    "IncidentResponseRequest",
    "NotificationResult",
    "PollingManagerInput",
    "PollingProviderConfig",
    "RiskScore",
    "TenantConfig",
    "TicketData",
    "TicketCreationRequest",
    "TicketResult",
    "TicketingProvider",
    "ThreatIntelEnrichmentRequest",
    "ThreatIntelResult",
    "TriageRequest",
    "TriageResult",
    "AITriageProvider",
    "UserDeprovisioningRequest",
    # ingress
    "IamIngressRequest",
    # canonical
    "Correlation",
    "DefenderDetectionFindingEvent",
    "Envelope",
    "HitlApprovalEvent",
    "IamOnboardingEvent",
    "ImpossibleTravelEvent",
    "StoragePartition",
    "VendorExtension",
    "VendorExtensions",
    "derive_event_id",
    # canonical helper mappers
    "build_connector_correlation",
    "build_envelope",
    "build_storage_partition",
    "to_approval_decision",
]
