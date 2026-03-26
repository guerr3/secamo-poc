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

    model_config = ConfigDict(extra="forbid")


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


class ImpossibleTravelEvent(StrictModel):
    """OCSF Authentication payload for impossible-travel detections."""

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


class HitlApprovalEvent(StrictModel):
    """First-class HiTL approval payload for callback-driven decisions."""

    event_type: Literal["hitl.approval"]
    category_uid: Literal[0] = 0
    class_uid: Literal[0] = 0
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
    | ImpossibleTravelEvent
    | DefenderDetectionFindingEvent
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


# Transitional compatibility models kept for non-migrated connectors/mappers.
class AlertData(StrictModel):
    alert_id: str
    severity: str = "medium"
    title: str = ""
    description: str = ""
    device_id: str | None = None
    user_email: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None


class UserContext(StrictModel):
    user_principal_name: str | None = None
    action: LifecycleAction | None = None
    user_data: dict[str, JsonValue] = Field(default_factory=dict)


class DeviceContext(StrictModel):
    device_id: str | None = None
    hostname: str | None = None


class NetworkContext(StrictModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    location: str | None = None


class SecurityEvent(StrictModel):
    event_id: str
    event_type: str
    tenant_id: str
    source_provider: str
    requester: str = "ingress-api"
    severity: str | None = None
    correlation_id: str | None = None
    ticket_id: str | None = None
    alert: AlertData | None = None
    user: UserContext | None = None
    device: DeviceContext | None = None
    network: NetworkContext | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class CanonicalEvent(StrictModel):
    event_type: str
    tenant_id: str
    provider: str
    external_event_id: str | None = None
    subject: str
    severity: str | None = None
    occurred_at: datetime | None = None
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    actor: dict[str, JsonValue] | None = None
    request_id: str | None = None
    correlation_id: str | None = None


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
    "Correlation",
    "CanonicalEvent",
    "AlertData",
    "DeviceContext",
    "DefenderDetectionFindingEvent",
    "Envelope",
    "HitlApprovalEvent",
    "IamOnboardingEvent",
    "ImpossibleTravelEvent",
    "NetworkContext",
    "SecurityEvent",
    "SecamoEventVariant",
    "SecamoEventVariantAdapter",
    "StoragePartition",
    "UserContext",
    "VendorExtension",
    "VendorExtensions",
    "derive_event_id",
]
