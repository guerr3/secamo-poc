"""Tests for deterministic event identity derivation across the dedup pipeline.

Validates that envelope_builder, normalization, and polling_manager produce
stable IDs without UUID fallbacks.
"""

from __future__ import annotations

from datetime import datetime, timezone

from shared.ingress.envelope_builder import (
    _deterministic_payload_hash,
    _resolve_provider_event_id,
    build_envelope,
)
from shared.ingress.normalization import normalize_event_body


# -- _resolve_provider_event_id tests -----------------------------------------


def test_resolve_provider_event_id_prefers_normalized_event_id() -> None:
    result = _resolve_provider_event_id(
        normalized={"event_id": "norm-evt-1"},
        raw_body={"event_id": "raw-evt-1"},
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    assert result == "norm-evt-1"


def test_resolve_provider_event_id_falls_back_to_raw_event_id() -> None:
    result = _resolve_provider_event_id(
        normalized={},
        raw_body={"event_id": "raw-evt-2"},
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    assert result == "raw-evt-2"


def test_resolve_provider_event_id_falls_back_to_correlation_id() -> None:
    result = _resolve_provider_event_id(
        normalized={},
        raw_body={"correlation_id": "corr-123"},
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    assert result == "corr-123"


def test_resolve_provider_event_id_falls_back_to_request_id() -> None:
    result = _resolve_provider_event_id(
        normalized={},
        raw_body={"request_id": "req-456"},
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    assert result == "req-456"


def test_resolve_provider_event_id_produces_deterministic_hash_as_last_resort() -> None:
    """When no stable ID is found, a deterministic hash is produced (no UUID)."""
    raw_body = {"title": "Suspicious login", "severity": "high"}
    result_a = _resolve_provider_event_id(
        normalized={},
        raw_body=raw_body,
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    result_b = _resolve_provider_event_id(
        normalized={},
        raw_body=raw_body,
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    assert result_a == result_b, "Hash must be deterministic across calls"
    assert len(result_a) == 64, "Hash must be SHA-256 hex digest"


def test_resolve_provider_event_id_hash_differs_for_different_payloads() -> None:
    """Different raw bodies must produce different hashes."""
    result_a = _resolve_provider_event_id(
        normalized={},
        raw_body={"title": "Alpha"},
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    result_b = _resolve_provider_event_id(
        normalized={},
        raw_body={"title": "Beta"},
        tenant_id="t1",
        event_type="alert",
        provider="defender",
    )
    assert result_a != result_b


# -- _deterministic_payload_hash tests ----------------------------------------


def test_deterministic_payload_hash_is_stable() -> None:
    raw_body = {"key": "value", "nested": {"a": 1}}
    h1 = _deterministic_payload_hash(
        tenant_id="t1", event_type="alert", provider="defender", raw_body=raw_body,
    )
    h2 = _deterministic_payload_hash(
        tenant_id="t1", event_type="alert", provider="defender", raw_body=raw_body,
    )
    assert h1 == h2
    assert len(h1) == 64


def test_deterministic_payload_hash_includes_tenant_id_discrimination() -> None:
    """Same payload from different tenants must produce different hashes."""
    raw_body = {"title": "Same event"}
    h1 = _deterministic_payload_hash(
        tenant_id="tenant-a", event_type="alert", provider="defender", raw_body=raw_body,
    )
    h2 = _deterministic_payload_hash(
        tenant_id="tenant-b", event_type="alert", provider="defender", raw_body=raw_body,
    )
    assert h1 != h2


# -- normalize_event_body deterministic fallback tests -------------------------


def test_normalize_unknown_event_produces_deterministic_id_from_raw_event_id() -> None:
    """Unknown normalizer path should use raw_body event_id when available."""
    result = normalize_event_body(
        provider="custom_siem",
        event_type="custom.event",
        tenant_id="t1",
        raw_body={"event_id": "custom-evt-123", "severity": "high"},
    )
    assert result["event_id"] == "custom-evt-123"


def test_normalize_unknown_event_produces_deterministic_hash_when_no_id() -> None:
    """Unknown normalizer path must not produce weak provider-tenant fallback."""
    raw_body = {"title": "Unknown event", "data": "payload"}
    result_a = normalize_event_body(
        provider="custom_siem",
        event_type="custom.event",
        tenant_id="t1",
        raw_body=raw_body,
    )
    result_b = normalize_event_body(
        provider="custom_siem",
        event_type="custom.event",
        tenant_id="t1",
        raw_body=raw_body,
    )
    assert result_a["event_id"] == result_b["event_id"]
    assert len(result_a["event_id"]) == 64, "Should be a SHA-256 hex digest"
    # Must NOT be the old weak fallback pattern.
    assert result_a["event_id"] != "custom_siem-t1"


def test_normalize_unknown_event_different_payloads_produce_different_ids() -> None:
    """Different raw bodies must produce different deterministic IDs."""
    result_a = normalize_event_body(
        provider="custom_siem",
        event_type="custom.event",
        tenant_id="t1",
        raw_body={"title": "Event A"},
    )
    result_b = normalize_event_body(
        provider="custom_siem",
        event_type="custom.event",
        tenant_id="t1",
        raw_body={"title": "Event B"},
    )
    assert result_a["event_id"] != result_b["event_id"]
