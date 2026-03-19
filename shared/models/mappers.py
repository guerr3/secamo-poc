"""
shared.models.mappers — Conversion functions between model layers.

Envelope → ProviderEvent → CanonicalEvent → WorkflowCommand
                                           → Domain contracts
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shared.models.canonical import (
    AlertData,
    CanonicalEvent,
    DeviceContext,
    NetworkContext,
    SecurityEvent,
    UserContext,
)
from shared.models.commands import (
    SignalWorkflowCommand,
    StartWorkflowCommand,
    WorkflowCommand,
)
from shared.models.common import LifecycleAction
from shared.models.domain import ApprovalDecision
from shared.models.ingress import IamIngressRequest, RawIngressEnvelope
from shared.models.provider_events import (
    DefenderWebhook,
    ProviderEvent,
    TeamsApprovalCallback,
)


PROVIDER_EVENT_ROUTING: dict[tuple[str, str], tuple[str, str]] = {
    ("microsoft_defender", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_defender", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("crowdstrike", "detection_summary"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("crowdstrike", "impossible_travel"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("sentinelone", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("jira", "jira:issue_created"): ("IamOnboardingWorkflow", "iam-graph"),
    ("jira", "jira:issue_updated"): ("IamOnboardingWorkflow", "iam-graph"),
    # Backwards-compatible alias used by current webhook mapper/tests.
    ("defender", "alert"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
}

POLLING_RESOURCE_EVENT_TYPES: dict[tuple[str, str], str] = {
    ("microsoft_defender", "defender_alerts"): "alert",
    ("microsoft_defender", "entra_signin_logs"): "impossible_travel",
}

WEBHOOK_RESOURCE_ROUTING: dict[tuple[str, str], tuple[str, str]] = {
    ("microsoft_graph", "security/alerts"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_graph", "security/alerts_v2"): ("DefenderAlertEnrichmentWorkflow", "soc-defender"),
    ("microsoft_graph", "auditlogs/signins"): ("ImpossibleTravelWorkflow", "soc-defender"),
    ("microsoft_graph", "identityprotection/riskyusers"): ("ImpossibleTravelWorkflow", "soc-defender"),
}


def resolve_provider_event_route(provider: str, event_type: str) -> tuple[str, str] | None:
    return PROVIDER_EVENT_ROUTING.get((provider.lower(), event_type.lower()))


def resolve_polling_route(provider: str, resource_type: str, payload: dict[str, Any] | None = None) -> tuple[str, str] | None:
    provider_key = provider.lower()
    resource_key = resource_type.lower()
    configured_event_type = POLLING_RESOURCE_EVENT_TYPES.get((provider_key, resource_key))
    if not configured_event_type:
        return None

    provider_event_type = configured_event_type
    if payload and payload.get("provider_event_type"):
        provider_event_type = str(payload["provider_event_type"])

    if not provider_event_type:
        return None
    return resolve_provider_event_route(provider, str(provider_event_type))


def resolve_webhook_route(provider: str, resource_type: str, payload: dict[str, Any] | None = None) -> tuple[str, str] | None:
    provider_key = provider.lower().strip()
    resource_key = resource_type.lower().strip().lstrip("/")

    if resource_key.count("/") >= 2:
        # Microsoft Graph often sends resources like security/alerts_v2/{id}.
        resource_key = resource_key.rsplit("/", 1)[0]

    direct = WEBHOOK_RESOURCE_ROUTING.get((provider_key, resource_key))
    if direct is not None:
        return direct

    if payload and payload.get("provider_event_type"):
        return resolve_provider_event_route(provider, str(payload["provider_event_type"]))

    return None


# ── Envelope → ProviderEvent ──────────────────────────────────

_PROVIDER_MAP: dict[str, type[ProviderEvent]] = {
    "defender": DefenderWebhook,
    "teams": TeamsApprovalCallback,
}


def build_provider_event(envelope: RawIngressEnvelope) -> ProviderEvent:
    """
    Parse the raw envelope body into the correct ProviderEvent subtype
    based on ``envelope.provider``.

    Raises:
        ValueError: For unknown providers.
    """
    provider_cls = _PROVIDER_MAP.get(envelope.provider.lower())
    if provider_cls is None:
        raise ValueError(f"Unknown provider: {envelope.provider!r}")

    base_fields: dict[str, Any] = {
        "provider": envelope.provider,
        "event_name": f"{envelope.provider}.webhook",
        "tenant_id": envelope.tenant_id,
        "received_at": envelope.received_at,
        "raw_payload": envelope.raw_body if isinstance(envelope.raw_body, dict) else {},
    }

    payload = envelope.raw_body if isinstance(envelope.raw_body, dict) else {}
    return provider_cls.model_validate({**base_fields, **payload})


# ── ProviderEvent → CanonicalEvent ────────────────────────────

def to_canonical_event(
    provider_event: ProviderEvent,
    envelope: RawIngressEnvelope,
) -> CanonicalEvent:
    """Convert a provider event + envelope into a CanonicalEvent."""
    if isinstance(provider_event, DefenderWebhook):
        return _defender_to_canonical(provider_event, envelope)
    if isinstance(provider_event, TeamsApprovalCallback):
        return _teams_to_canonical(provider_event, envelope)
    raise ValueError(f"No canonical mapping for {type(provider_event).__name__}")


def _defender_to_canonical(
    event: DefenderWebhook, envelope: RawIngressEnvelope,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_type="defender.alert",
        tenant_id=envelope.tenant_id,
        provider="defender",
        external_event_id=event.alert_id,
        subject=event.title,
        severity=event.severity,
        occurred_at=event.occurred_at,
        request_id=envelope.request_id,
        payload={
            "alert_id": event.alert_id,
            "severity": event.severity,
            "title": event.title,
            "description": event.description,
            "device_id": event.device_id,
            "user_email": event.user_email,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
        },
    )


def _teams_to_canonical(
    event: TeamsApprovalCallback, envelope: RawIngressEnvelope,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_type="teams.approval_callback",
        tenant_id=envelope.tenant_id,
        provider="teams",
        subject=f"approval:{event.workflow_id}",
        occurred_at=event.occurred_at,
        request_id=envelope.request_id,
        payload={
            "workflow_id": event.workflow_id,
            "approved": event.approved,
            "reviewer": event.reviewer,
            "action": event.action,
            "comments": event.comments,
        },
    )


def iam_request_to_canonical(
    request: IamIngressRequest,
    tenant_id: str,
    request_id: str | None = None,
) -> CanonicalEvent:
    """Convert a first-party IamIngressRequest into a CanonicalEvent."""
    return CanonicalEvent(
        event_type="iam.onboarding",
        tenant_id=tenant_id,
        provider="iam-api",
        subject=request.user_data.get("email", ""),
        actor={"requester": request.requester},
        occurred_at=datetime.now(timezone.utc),
        request_id=request_id,
        payload={
            "action": request.action,
            "user_data": request.user_data,
            "requester": request.requester,
            "ticket_id": request.ticket_id or "",
        },
    )


# ── CanonicalEvent → WorkflowCommand ─────────────────────────

_EVENT_TYPE_TO_WORKFLOW: dict[str, dict[str, str]] = {
    "defender.alert": {
        "workflow_name": "DefenderAlertEnrichmentWorkflow",
        "task_queue": "soc-defender",
    },
    "iam.onboarding": {
        "workflow_name": "IamOnboardingWorkflow",
        "task_queue": "iam-graph",
    },
}

_CANONICAL_EVENT_TO_PROVIDER_ROUTE: dict[str, tuple[str, str]] = {
    "defender.alert": ("microsoft_defender", "alert"),
}


def to_workflow_command(event: CanonicalEvent) -> WorkflowCommand:
    """
    Generate a StartWorkflowCommand or SignalWorkflowCommand from a
    CanonicalEvent, based on ``event_type``.
    """
    # Signals
    if event.event_type == "teams.approval_callback":
        return SignalWorkflowCommand(
            tenant_id=event.tenant_id,
            workflow_id=event.payload["workflow_id"],
            signal_name="approve",
            signal_payload={
                "approved": event.payload["approved"],
                "reviewer": event.payload["reviewer"],
                "action": event.payload["action"],
                "comments": event.payload.get("comments", ""),
            },
        )

    # Workflow starts
    provider_route = _CANONICAL_EVENT_TO_PROVIDER_ROUTE.get(event.event_type)
    if provider_route is not None:
        routed = resolve_provider_event_route(provider_route[0], provider_route[1])
        if routed is not None:
            workflow_name, task_queue = routed
            return StartWorkflowCommand(
                tenant_id=event.tenant_id,
                workflow_name=workflow_name,
                task_queue=task_queue,
                workflow_input=to_security_event(event),
            )

    mapping = _EVENT_TYPE_TO_WORKFLOW.get(event.event_type)
    if mapping is None:
        raise ValueError(f"No workflow mapping for event_type={event.event_type!r}")

    return StartWorkflowCommand(
        tenant_id=event.tenant_id,
        workflow_name=mapping["workflow_name"],
        task_queue=mapping["task_queue"],
        workflow_input=to_security_event(event),
    )


# ── CanonicalEvent → Universal Workflow Contract ──────────────

def _event_identity(event: CanonicalEvent) -> str:
    occurred = event.occurred_at.isoformat() if event.occurred_at else "na"
    return (
        event.external_event_id
        or event.request_id
        or f"{event.tenant_id}:{event.event_type}:{occurred}"
    )


def to_security_event(event: CanonicalEvent) -> SecurityEvent:
    """Convert CanonicalEvent into universal SecurityEvent workflow input."""
    payload = event.payload or {}

    alert_payload = payload.get("alert", payload)
    alert = None
    if event.event_type in {"defender.alert", "defender.impossible_travel"}:
        alert = AlertData.model_validate(
            {
                "alert_id": alert_payload.get("alert_id") or event.external_event_id or "",
                "severity": alert_payload.get("severity") or event.severity or "medium",
                "title": alert_payload.get("title") or event.subject or "Security alert",
                "description": alert_payload.get("description") or "",
                "device_id": alert_payload.get("device_id"),
                "user_email": alert_payload.get("user_email"),
                "source_ip": alert_payload.get("source_ip"),
                "destination_ip": alert_payload.get("destination_ip"),
            }
        )

    user = None
    if event.event_type == "iam.onboarding":
        user_data = payload.get("user_data", {})
        action = payload.get("action")
        user = UserContext(
            user_principal_name=user_data.get("email"),
            action=LifecycleAction(action) if action else None,
            user_data=user_data,
        )
    elif alert and alert.user_email:
        user = UserContext(user_principal_name=alert.user_email)

    device = None
    if alert and alert.device_id:
        device = DeviceContext(device_id=alert.device_id)

    network = None
    source_ip = alert.source_ip if alert else payload.get("source_ip")
    destination_ip = alert.destination_ip if alert else payload.get("destination_ip")
    if source_ip or destination_ip or payload.get("location"):
        network = NetworkContext(
            source_ip=source_ip,
            destination_ip=destination_ip,
            location=payload.get("location"),
        )

    known_keys = {
        "alert",
        "alert_id",
        "severity",
        "title",
        "description",
        "device_id",
        "user_email",
        "source_ip",
        "destination_ip",
        "action",
        "user_data",
        "requester",
        "ticket_id",
        "location",
    }
    metadata = {k: v for k, v in payload.items() if k not in known_keys}

    return SecurityEvent(
        event_id=_event_identity(event),
        tenant_id=event.tenant_id,
        event_type=event.event_type,
        source_provider=event.provider,
        requester=payload.get("requester", "ingress-api"),
        severity=(alert.severity if alert else event.severity),
        correlation_id=event.correlation_id,
        ticket_id=payload.get("ticket_id"),
        alert=alert,
        user=user,
        device=device,
        network=network,
        metadata=metadata,
    )


def to_approval_decision(event: CanonicalEvent) -> ApprovalDecision:
    """Convert a canonical Teams callback into an ApprovalDecision."""
    return ApprovalDecision(
        approved=event.payload["approved"],
        reviewer=event.payload["reviewer"],
        action=event.payload["action"],
        comments=event.payload.get("comments", ""),
    )
