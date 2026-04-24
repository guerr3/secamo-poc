"""Canonical OCSF-aligned models used by ingress, routing, and workflows.

This module intentionally contains only strict, non-legacy contracts.
Tenant identity is route-derived and must not be header-derived.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Annotated, Literal, TypeAlias
from typing_extensions import TypeAliasType

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from shared.models.common import LifecycleAction


JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue = TypeAliasType("JsonValue", JsonScalar | list["JsonValue"] | dict[str, "JsonValue"])


class StrictModel(BaseModel):
    """Base strict model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class StoragePartition(StrictModel):
    """Correlation-aware storage partition hints for persistence layers."""

    ddb_pk: str
    ddb_sk: str
    s3_bucket: str
    s3_key_prefix: str


class Correlation(StrictModel):
    """Structured cross-system correlation context."""

    correlation_id: str
    causation_id: str
    request_id: str
    trace_id: str
    parent_event_id: str | None = None
    storage_partition: StoragePartition


class VendorExtension(StrictModel):
    """Typed vendor extension record for provider-specific enrichment."""

    source: str
    value: JsonValue


VendorExtensions: TypeAlias = dict[str, VendorExtension]


class IamOnboardingEvent(StrictModel):
    """OCSF IAM Account Change payload for onboarding lifecycle events."""

    event_type: Literal["iam.onboarding"]
    category_uid: Literal[3] = 3
    class_uid: Literal[3001] = 3001
    activity_id: int
    activity_name: str | None = None
    user_email: str
    action: LifecycleAction
    user_data: dict[str, JsonValue] = Field(default_factory=dict)
    message: str | None = None
    vendor_extensions: VendorExtensions = Field(default_factory=dict)


class CustomerOnboardingEvent(StrictModel):
    """OCSF IAM Account Change payload for tenant onboarding lifecycle events."""

    event_type: Literal["customer.onboarding"]
    category_uid: Literal[3] = 3
    class_uid: Literal[3003] = 3003
    activity_id: int
    activity_name: str | None = None
    tenant_id: str
    display_name: str | None = None
    action: LifecycleAction = LifecycleAction.CREATE
    config: dict[str, JsonValue] = Field(default_factory=dict)
    secrets: dict[str, dict[str, JsonValue]] = Field(default_factory=dict)
    soc_analyst_email: str | None = None
    welcome_email: str | None = None
    message: str | None = None
    vendor_extensions: VendorExtensions = Field(default_factory=dict)


class AuthenticationEvent(StrictModel):
    """OCSF Authentication payload for sign-in events (Class 3002)."""

    event_type: Literal["defender.impossible_travel"]
    category_uid: Literal[3] = 3
    class_uid: Literal[3002] = 3002
    activity_id: int
    activity_name: str | None = None
    user_principal_name: str
    source_ip: str
    destination_ip: str | None = None
    location: str | None = None
    severity_id: int
    severity: str | None = None
    message: str | None = None
    vendor_extensions: VendorExtensions = Field(default_factory=dict)


class AuditLogRecord(StrictModel):
    """Structured audit log record for workflow lifecycle tracking."""

    PK: str
    SK: str
    workflow_id: str
    tenant_id: str
    event_type: str
    message: str
    alert_id: str | None = None
    ticket_id: str | None = None
    case_type: str | None = None
    ttl: int | None = None


class DefenderDetectionFindingEvent(StrictModel):
    """OCSF Detection Finding payload for Defender alert events."""

    event_type: Literal["defender.alert"]
    category_uid: Literal[2] = 2
    class_uid: Literal[2004] = 2004
    activity_id: int
    activity_name: str | None = None
    alert_id: str
    title: str
    description: str | None = None
    severity_id: int
    severity: str | None = None
    status_id: int | None = None
    status: str | None = None
    message: str | None = None
    vendor_extensions: VendorExtensions = Field(default_factory=dict)


class DefenderSecuritySignalEvent(StrictModel):
    """Generic provider-agnostic signal payload for non-alert Defender resources."""

    event_type: Literal["defender.security_signal"]
    # Custom extension UIDs (non-zero) reserved for generic provider signal events.
    category_uid: Literal[99] = 99
    class_uid: Literal[990002] = 990002
    activity_id: int
    activity_name: str | None = None
    signal_id: str
    provider_event_type: str
    resource_type: str
    title: str
    description: str | None = None
    severity_id: int
    severity: str | None = None
    status_id: int | None = None
    status: str | None = None
    message: str | None = None
    vendor_extensions: VendorExtensions = Field(default_factory=dict)


class HitlApprovalEvent(StrictModel):
    """First-class HiTL approval payload for callback-driven decisions."""

    event_type: Literal["hitl.approval"]
    # Custom extension UIDs (non-zero) reserved for Secamo-specific approval events.
    category_uid: Literal[99] = 99
    class_uid: Literal[990001] = 990001
    activity_id: int
    activity_name: str | None = None
    approval_id: str
    decision: Literal["approved", "rejected", "timed_out", "cancelled"]
    channel: Literal["email", "jira", "slack", "teams", "web"]
    responder: str | None = None
    reason: str | None = None
    vendor_extensions: VendorExtensions = Field(default_factory=dict)


SecamoEventVariant: TypeAlias = Annotated[
    IamOnboardingEvent
    | CustomerOnboardingEvent
    | AuthenticationEvent
    | DefenderDetectionFindingEvent
    | DefenderSecuritySignalEvent
    | HitlApprovalEvent,
    Field(discriminator="event_type"),
]


SecamoEventVariantAdapter = TypeAdapter(SecamoEventVariant)


class Envelope(StrictModel):
    """Immutable envelope for all canonical orchestration events.

    `tenant_id` must come from route path extraction and is never header-derived.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    tenant_id: str
    source_provider: str
    event_name: str
    schema_version: str
    event_version: str
    ocsf_version: str
    occurred_at: datetime
    correlation: Correlation
    payload: SecamoEventVariant
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    raw_data_ref: str | None = None


def derive_event_id(
    *,
    tenant_id: str,
    event_type: str,
    occurred_at: datetime,
    correlation_id: str,
    provider_event_id: str | None = None,
) -> str:
    """Build a deterministic event identifier for idempotent orchestration."""

    normalized_time = occurred_at.astimezone(timezone.utc).isoformat(timespec="microseconds")
    seed = {
        "tenant_id": tenant_id,
        "event_type": event_type,
        "occurred_at": normalized_time,
        "correlation_id": correlation_id,
        "provider_event_id": provider_event_id or "",
    }
    canonical_seed = json.dumps(seed, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_seed.encode("utf-8")).hexdigest()


__all__ = [
    "AuditLogRecord",
    "AuthenticationEvent",
    "Correlation",
    "CustomerOnboardingEvent",
    "DefenderDetectionFindingEvent",
    "DefenderSecuritySignalEvent",
    "Envelope",
    "HitlApprovalEvent",
    "IamOnboardingEvent",
    "SecamoEventVariant",
    "SecamoEventVariantAdapter",
    "StoragePartition",
    "VendorExtension",
    "VendorExtensions",
    "derive_event_id",
]
