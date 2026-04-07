"""shared.models.mappers — Canonical envelope helper functions.

This module provides reusable canonical model helpers used by connectors and
approval callback translation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from shared.models.canonical import (
    Correlation,
    CustomerOnboardingEvent,
    DefenderDetectionFindingEvent,
    Envelope,
    HitlApprovalEvent,
    IamOnboardingEvent,
    ImpossibleTravelEvent,
    StoragePartition,
    VendorExtension,
    derive_event_id,
)
from shared.models.domain import ApprovalDecision


def _storage_partition(tenant_id: str, event_name: str, provider_event_id: str | None) -> StoragePartition:
    event_suffix = provider_event_id or "ingress"
    normalized_event = event_name.replace(".", "#")
    return StoragePartition(
        ddb_pk=f"TENANT#{tenant_id}",
        ddb_sk=f"EVENT#{normalized_event}#{event_suffix}",
        s3_bucket=f"secamo-events-{tenant_id}",
        s3_key_prefix=f"raw/{event_name}/{event_suffix}",
    )


def build_storage_partition(tenant_id: str, event_name: str, provider_event_id: str | None) -> StoragePartition:
    """Build deterministic storage partition hints for canonical events."""

    return _storage_partition(tenant_id, event_name, provider_event_id)


def build_connector_correlation(
    *,
    tenant_id: str,
    event_name: str,
    correlation_id: str,
    provider_event_id: str | None,
) -> Correlation:
    """Build connector-centric correlation where request/trace align with correlation id."""

    return Correlation(
        correlation_id=correlation_id,
        causation_id=correlation_id,
        request_id=correlation_id,
        trace_id=correlation_id,
        storage_partition=_storage_partition(tenant_id, event_name, provider_event_id),
    )


def build_envelope(
    *,
    tenant_id: str,
    source_provider: str,
    occurred_at: datetime,
    payload: (
        DefenderDetectionFindingEvent
        | ImpossibleTravelEvent
        | IamOnboardingEvent
        | CustomerOnboardingEvent
        | HitlApprovalEvent
    ),
    correlation: Correlation,
    provider_event_id: str | None,
    metadata: dict[str, Any] | None = None,
) -> Envelope:
    """Create a canonical envelope from typed payload and correlation context."""

    return Envelope(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            event_type=payload.event_type,
            occurred_at=occurred_at,
            correlation_id=correlation.correlation_id,
            provider_event_id=provider_event_id,
        ),
        tenant_id=tenant_id,
        source_provider=source_provider,
        event_name=payload.event_type,
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=occurred_at,
        correlation=correlation,
        payload=payload,
        metadata=metadata or {},
    )


def to_approval_decision(envelope: Envelope) -> ApprovalDecision:
    if not isinstance(envelope.payload, HitlApprovalEvent):
        raise ValueError("Approval decision conversion requires hitl.approval envelope payload")

    action_ext = envelope.payload.vendor_extensions.get("action")
    action = str(action_ext.value) if action_ext is not None else "dismiss"
    return ApprovalDecision(
        approved=envelope.payload.decision == "approved",
        reviewer=envelope.payload.responder or "unknown",
        action=action,
        comments=envelope.payload.reason or "",
    )


__all__ = [
    "build_connector_correlation",
    "build_envelope",
    "build_storage_partition",
    "to_approval_decision",
]
