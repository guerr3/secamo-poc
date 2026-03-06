"""
shared.models.mappers — Conversion functions between model layers.

Envelope → ProviderEvent → CanonicalEvent → WorkflowCommand
                                           → Domain contracts
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shared.models.canonical import CanonicalEvent
from shared.models.commands import (
    SignalWorkflowCommand,
    StartWorkflowCommand,
    WorkflowCommand,
)
from shared.models.common import LifecycleAction
from shared.models.domain import (
    AlertData,
    ApprovalDecision,
    DefenderAlertRequest,
    LifecycleRequest,
    UserData,
)
from shared.models.ingress import IamIngressRequest, RawIngressEnvelope
from shared.models.provider_events import (
    DefenderWebhook,
    ProviderEvent,
    TeamsApprovalCallback,
)


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
    mapping = _EVENT_TYPE_TO_WORKFLOW.get(event.event_type)
    if mapping is None:
        raise ValueError(f"No workflow mapping for event_type={event.event_type!r}")

    return StartWorkflowCommand(
        tenant_id=event.tenant_id,
        workflow_name=mapping["workflow_name"],
        task_queue=mapping["task_queue"],
        workflow_input=event.payload,
    )


# ── CanonicalEvent → Domain Contracts ─────────────────────────

def to_lifecycle_request(event: CanonicalEvent) -> LifecycleRequest:
    """Convert a canonical IAM event into a LifecycleRequest."""
    return LifecycleRequest(
        tenant_id=event.tenant_id,
        action=LifecycleAction(event.payload["action"]),
        user_data=UserData.model_validate(event.payload["user_data"]),
        requester=event.payload.get("requester", "ingress-api"),
        ticket_id=event.payload.get("ticket_id", ""),
    )


def to_defender_alert_request(event: CanonicalEvent) -> DefenderAlertRequest:
    """Convert a canonical Defender event into a DefenderAlertRequest."""
    return DefenderAlertRequest(
        tenant_id=event.tenant_id,
        alert=AlertData.model_validate(event.payload),
        requester=event.payload.get("requester", "ingress-api"),
    )


def to_approval_decision(event: CanonicalEvent) -> ApprovalDecision:
    """Convert a canonical Teams callback into an ApprovalDecision."""
    return ApprovalDecision(
        approved=event.payload["approved"],
        reviewer=event.payload["reviewer"],
        action=event.payload["action"],
        comments=event.payload.get("comments", ""),
    )
