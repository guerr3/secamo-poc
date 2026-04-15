from __future__ import annotations

from datetime import datetime, timezone

from shared.models.canonical import (
    Correlation,
    DefenderDetectionFindingEvent,
    Envelope,
    ImpossibleTravelEvent,
    StoragePartition,
    VendorExtension,
)
from shared.normalization import (
    normalize_defender_alert_case,
    normalize_impossible_travel_case,
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
