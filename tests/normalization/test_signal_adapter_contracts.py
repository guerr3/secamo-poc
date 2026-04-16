from __future__ import annotations

from datetime import datetime, timezone

import pytest

from shared.models.canonical import (
    Correlation,
    DefenderSecuritySignalEvent,
    Envelope,
    StoragePartition,
    VendorExtension,
)
from shared.normalization.soc import (
    normalize_audit_log_case,
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
            ddb_sk="EVENT#defender#security_signal#evt-1",
            s3_bucket="secamo-events-tenant-1",
            s3_key_prefix="raw/defender.security_signal/evt-1",
        ),
    )


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


def test_signin_log_adapter_correct_allowed_actions() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-signin-1",
        provider_event_type="signin_log",
        vendor_extensions={
            "user_email": VendorExtension(source="test", value="alice@example.com"),
        },
    )

    case = normalize_signin_log_case(envelope, auto_remediate=False)

    assert "isolate_device" not in case.allowed_actions
    assert "run_antivirus_scan" not in case.allowed_actions


def test_risky_user_adapter_allowed_actions_contain_confirm_compromised() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-risky-1",
        provider_event_type="risky_user",
        vendor_extensions={
            "user_principal_name": VendorExtension(source="test", value="risky.user@example.com"),
        },
    )

    case = normalize_risky_user_case(envelope, auto_remediate=False)

    assert "confirm_compromised" in case.allowed_actions


def test_noncompliant_device_adapter_requires_device_id_extension() -> None:
    envelope = _security_signal_envelope(
        event_id="evt-device-1",
        provider_event_type="noncompliant_device",
        vendor_extensions={
            "user_email": VendorExtension(source="test", value="owner@example.com"),
        },
    )

    case = normalize_noncompliant_device_case(envelope, auto_remediate=False)

    assert case.device is None


@pytest.mark.parametrize("provider_event_type", ["signin_log", "risky_user", "noncompliant_device", "unknown"])
def test_audit_log_adapter_rejects_non_audit_provider_event_type(provider_event_type: str) -> None:
    envelope = _security_signal_envelope(
        event_id=f"evt-audit-{provider_event_type}",
        provider_event_type=provider_event_type,
    )

    with pytest.raises(ValueError):
        normalize_audit_log_case(envelope, auto_remediate=False)


@pytest.mark.parametrize(
    "normalizer,provider_event_type",
    [
        (normalize_signin_log_case, "signin_log"),
        (normalize_risky_user_case, "risky_user"),
        (normalize_noncompliant_device_case, "noncompliant_device"),
        (normalize_audit_log_case, "audit_log"),
    ],
)
def test_all_adapters_set_auto_remediate_from_kwarg(normalizer, provider_event_type: str) -> None:
    envelope = _security_signal_envelope(
        event_id=f"evt-{provider_event_type}",
        provider_event_type=provider_event_type,
    )

    true_case = normalizer(envelope, auto_remediate=True)
    false_case = normalizer(envelope, auto_remediate=False)

    assert true_case.auto_remediate is True
    assert false_case.auto_remediate is False


@pytest.mark.parametrize(
    "normalizer,provider_event_type",
    [
        (normalize_signin_log_case, "signin_log"),
        (normalize_risky_user_case, "risky_user"),
        (normalize_noncompliant_device_case, "noncompliant_device"),
        (normalize_audit_log_case, "audit_log"),
    ],
)
def test_all_adapters_populate_source_event(normalizer, provider_event_type: str) -> None:
    envelope = _security_signal_envelope(
        event_id=f"evt-source-{provider_event_type}",
        provider_event_type=provider_event_type,
    )

    case = normalizer(envelope, auto_remediate=False)

    assert case.source_event is envelope
