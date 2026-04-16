from __future__ import annotations

from datetime import datetime, timezone

import pytest

from shared.models.canonical import (
    Correlation,
    DefenderDetectionFindingEvent,
    DefenderSecuritySignalEvent,
    Envelope,
    ImpossibleTravelEvent,
    StoragePartition,
    VendorExtension,
)
from shared.normalization import (
    normalize_audit_log_case,
    normalize_defender_alert_case,
    normalize_impossible_travel_case,
    normalize_noncompliant_device_case,
    normalize_risky_user_case,
    normalize_signin_log_case,
)


def _correlation() -> Correlation:
    return Correlation(
        correlation_id="corr-1",
        causation_id="corr-1",
        request_id="req-1",
        trace_id="trace-1",
        storage_partition=StoragePartition(
            ddb_pk="TENANT#tenant-1",
            ddb_sk="EVENT#defender#alert#evt-1",
            s3_bucket="secamo-events-tenant-1",
            s3_key_prefix="raw/defender.alert/evt-1",
        ),
    )


def test_normalize_defender_alert_case_maps_identity_and_device() -> None:
    envelope = Envelope(
        event_id="evt-1",
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.alert",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=_correlation(),
        payload=DefenderDetectionFindingEvent(
            event_type="defender.alert",
            activity_id=2004,
            alert_id="alert-1",
            title="Test alert",
            severity_id=60,
            severity="high",
            vendor_extensions={
                "user_email": VendorExtension(source="test", value="analyst@example.com"),
                "device_id": VendorExtension(source="test", value="device-123"),
            },
        ),
    )

    case = normalize_defender_alert_case(envelope, auto_remediate=True)

    assert case.case_type == "defender_alert"
    assert case.severity == "high"
    assert case.identity == "analyst@example.com"
    assert case.device == "device-123"
    assert case.auto_remediate is True


def test_normalize_impossible_travel_case_sets_expected_defaults() -> None:
    envelope = Envelope(
        event_id="evt-2",
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.impossible_travel",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=_correlation(),
        payload=ImpossibleTravelEvent(
            event_type="defender.impossible_travel",
            activity_id=3002,
            user_principal_name="user@example.com",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            severity_id=60,
            severity="high",
        ),
    )

    case = normalize_impossible_travel_case(envelope, auto_remediate=False)

    assert case.case_type == "impossible_travel"
    assert case.alert_id == "evt-2"
    assert case.identity == "user@example.com"
    assert case.auto_remediate is False


def _security_signal_envelope(
    *,
    event_id: str,
    provider_event_type: str,
    severity: str = "high",
    vendor_extensions: dict[str, VendorExtension] | None = None,
) -> Envelope:
    return Envelope(
        event_id=event_id,
        tenant_id="tenant-1",
        source_provider="microsoft_defender",
        event_name="defender.security_signal",
        schema_version="1.0.0",
        event_version="1.0.0",
        ocsf_version="1.1.0",
        occurred_at=datetime.now(timezone.utc),
        correlation=_correlation(),
        payload=DefenderSecuritySignalEvent(
            event_type="defender.security_signal",
            activity_id=2100,
            activity_name="poller.fetch",
            signal_id=f"sig-{event_id}",
            provider_event_type=provider_event_type,
            resource_type=f"resource-{provider_event_type}",
            title=f"Title {provider_event_type}",
            severity_id=60,
            severity=severity,
            vendor_extensions=vendor_extensions or {},
        ),
    )


def test_normalize_signin_log_case_prefers_user_email_extension() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-signin-1",
        provider_event_type="signin_log",
        vendor_extensions={
            "user_email": VendorExtension(source="test", value="alice@example.com"),
            "user_principal_name": VendorExtension(source="test", value="alice-upn@example.com"),
            "device_id": VendorExtension(source="test", value="device-42"),
        },
    )

    case = normalize_signin_log_case(envelope, auto_remediate=False)

    assert case.case_type == "signin_log"
    assert case.alert_id == "sig-evt-signin-1"
    assert case.identity == "alice@example.com"
    assert case.device == "device-42"


def test_normalize_risky_user_case_falls_back_to_upn() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-risky-1",
        provider_event_type="risky_user",
        vendor_extensions={
            "user_principal_name": VendorExtension(source="test", value="risky.user@example.com"),
        },
    )

    case = normalize_risky_user_case(envelope, auto_remediate=True)

    assert case.case_type == "risky_user"
    assert case.identity == "risky.user@example.com"
    assert case.auto_remediate is True


def test_normalize_noncompliant_device_case_maps_device_id() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-device-1",
        provider_event_type="noncompliant_device",
        vendor_extensions={
            "device_id": VendorExtension(source="test", value="managed-device-100"),
        },
    )

    case = normalize_noncompliant_device_case(envelope, auto_remediate=False)

    assert case.case_type == "noncompliant_device"
    assert case.device == "managed-device-100"


def test_normalize_audit_log_case_rejects_wrong_provider_event_type() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-audit-1",
        provider_event_type="signin_log",
    )

    with pytest.raises(ValueError):
        normalize_audit_log_case(envelope, auto_remediate=False)


def test_normalize_audit_log_case_maps_identity_and_case_type() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-audit-2",
        provider_event_type="audit_log",
        vendor_extensions={
            "user_principal_name": VendorExtension(source="test", value="auditor@example.com"),
        },
    )

    case = normalize_audit_log_case(envelope, auto_remediate=False)

    assert case.case_type == "audit_log"
    assert case.identity == "auditor@example.com"
