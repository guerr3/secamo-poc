"""Regression tests for Graph webhook security-signal classification, normalization,
envelope building, and end-to-end route resolution.

These tests guard the fix applied across:
  - shared/ingress/graph.py        (classification)
  - shared/ingress/normalization.py (normalization)
  - shared/ingress/envelope_builder.py (envelope build)
  - shared/routing/defaults.py     (webhook resource mapping)

They must NOT exercise workflow, activity, or connector code.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from shared.ingress.envelope_builder import build_envelope
from shared.ingress.graph import GraphNotificationHelper
from shared.ingress.normalization import normalize_event_body
from shared.models.canonical import DefenderSecuritySignalEvent
from shared.routing.defaults import build_default_route_registry
from shared.routing.registry import RouteRegistry


# ---------------------------------------------------------------------------
# Seam 1: GraphNotificationHelper.graph_event_type_from_resource
# ---------------------------------------------------------------------------


class TestGraphEventTypeClassification:
    def test_signins_resource_classifies_as_security_signal(self) -> None:
        result = GraphNotificationHelper.graph_event_type_from_resource("auditLogs/signIns/abc-123")
        assert result == "defender.security_signal"

    def test_signins_resource_case_insensitive(self) -> None:
        result = GraphNotificationHelper.graph_event_type_from_resource("AUDITLOGS/SIGNINS")
        assert result == "defender.security_signal"

    def test_riskyusers_resource_classifies_as_security_signal(self) -> None:
        result = GraphNotificationHelper.graph_event_type_from_resource("identityProtection/riskyUsers/user-1")
        assert result == "defender.security_signal"

    def test_alerts_resource_still_classifies_as_defender_alert(self) -> None:
        result = GraphNotificationHelper.graph_event_type_from_resource("security/alerts_v2/alert-456")
        assert result == "defender.alert"

    def test_unknown_resource_returns_empty_string(self) -> None:
        result = GraphNotificationHelper.graph_event_type_from_resource("users/someone")
        assert result == ""


# ---------------------------------------------------------------------------
# Seam 2: normalize_event_body for microsoft_graph defender.security_signal
# ---------------------------------------------------------------------------


class TestGraphSecuritySignalNormalization:
    _TENANT = "tenant-demo-001"

    def _raw_signin(self, *, alert_id: str = "sg-001") -> dict:
        return {
            "resource": "auditLogs/signIns/sg-001",
            "alert": {
                "id": alert_id,
                "severity": "medium",
                "title": "Suspicious sign-in detected",
                "description": "Atypical travel",
                "userPrincipalName": "alice@example.com",
                "ipAddress": "203.0.113.1",
            },
        }

    def _raw_risky_user(self, *, alert_id: str = "ru-002") -> dict:
        return {
            "resource": "identityProtection/riskyUsers/ru-002",
            "alert": {
                "id": alert_id,
                "severity": "high",
                "riskEventType": "anonymizedIPAddress",
                "riskDetail": "User confirmed compromised",
                "userPrincipalName": "bob@example.com",
            },
        }

    def test_signin_normalizes_event_type(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_signin(),
        )
        assert payload["event_type"] == "defender.security_signal"

    def test_signin_normalizes_provider_event_type(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_signin(),
        )
        assert payload["provider_event_type"] == "signin_log"

    def test_signin_normalizes_resource_type(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_signin(),
        )
        assert payload["resource_type"] == "auditLogs/signIns"

    def test_signin_preserves_user_email(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_signin(),
        )
        assert payload["alert"]["user_email"] == "alice@example.com"

    def test_signin_preserves_source_ip(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_signin(),
        )
        assert payload["alert"]["source_ip"] == "203.0.113.1"

    def test_risky_user_normalizes_event_type(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_risky_user(),
        )
        assert payload["event_type"] == "defender.security_signal"

    def test_risky_user_normalizes_provider_event_type(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_risky_user(),
        )
        assert payload["provider_event_type"] == "risky_user"

    def test_risky_user_normalizes_resource_type(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_risky_user(),
        )
        assert payload["resource_type"] == "identityProtection/riskyUsers"

    def test_risky_user_preserves_user_email(self) -> None:
        payload = normalize_event_body(
            provider="microsoft_graph",
            event_type="defender.security_signal",
            tenant_id=self._TENANT,
            raw_body=self._raw_risky_user(),
        )
        assert payload["alert"]["user_email"] == "bob@example.com"


# ---------------------------------------------------------------------------
# Seam 3: build_envelope for defender.security_signal produces valid Envelope
# ---------------------------------------------------------------------------


class TestEnvelopeBuilderSecuritySignal:
    _TENANT = "tenant-demo-001"

    def _normalized_signin(self) -> dict:
        return {
            "event_id": "sg-001",
            "event_type": "defender.security_signal",
            "tenant_id": "tenant-demo-001",
            "source_provider": "microsoft_graph",
            "requester": "ingress-api",
            "severity": "medium",
            "provider_event_type": "signin_log",
            "resource_type": "auditLogs/signIns",
            "alert": {
                "alert_id": "sg-001",
                "severity": "medium",
                "title": "Suspicious sign-in detected",
                "description": "Atypical travel",
                "user_email": "alice@example.com",
                "source_ip": "203.0.113.1",
                "device_id": None,
            },
            "user": {"user_principal_name": "alice@example.com"},
            "metadata": {},
        }

    def _normalized_risky_user(self) -> dict:
        return {
            "event_id": "ru-002",
            "event_type": "defender.security_signal",
            "tenant_id": "tenant-demo-001",
            "source_provider": "microsoft_graph",
            "requester": "ingress-api",
            "severity": "high",
            "provider_event_type": "risky_user",
            "resource_type": "identityProtection/riskyUsers",
            "alert": {
                "alert_id": "ru-002",
                "severity": "high",
                "title": "anonymizedIPAddress",
                "description": "User confirmed compromised",
                "user_email": "bob@example.com",
                "source_ip": None,
                "device_id": None,
            },
            "user": {"user_principal_name": "bob@example.com"},
            "metadata": {},
        }

    def test_signin_envelope_builds_without_error(self) -> None:
        envelope = build_envelope(
            raw_body={"occurred_at": "2026-04-28T00:00:00Z"},
            normalized=self._normalized_signin(),
            provider="microsoft_graph",
            tenant_id=self._TENANT,
            event_type="defender.security_signal",
        )
        assert envelope is not None

    def test_signin_envelope_payload_is_defender_security_signal(self) -> None:
        envelope = build_envelope(
            raw_body={"occurred_at": "2026-04-28T00:00:00Z"},
            normalized=self._normalized_signin(),
            provider="microsoft_graph",
            tenant_id=self._TENANT,
            event_type="defender.security_signal",
        )
        assert isinstance(envelope.payload, DefenderSecuritySignalEvent)

    def test_signin_envelope_payload_provider_event_type(self) -> None:
        envelope = build_envelope(
            raw_body={"occurred_at": "2026-04-28T00:00:00Z"},
            normalized=self._normalized_signin(),
            provider="microsoft_graph",
            tenant_id=self._TENANT,
            event_type="defender.security_signal",
        )
        assert envelope.payload.provider_event_type == "signin_log"

    def test_signin_envelope_vendor_extensions_carry_user_email(self) -> None:
        envelope = build_envelope(
            raw_body={"occurred_at": "2026-04-28T00:00:00Z"},
            normalized=self._normalized_signin(),
            provider="microsoft_graph",
            tenant_id=self._TENANT,
            event_type="defender.security_signal",
        )
        ext = envelope.payload.vendor_extensions
        assert "user_email" in ext
        assert ext["user_email"].value == "alice@example.com"

    def test_risky_user_envelope_builds_without_error(self) -> None:
        envelope = build_envelope(
            raw_body={"occurred_at": "2026-04-28T00:00:00Z"},
            normalized=self._normalized_risky_user(),
            provider="microsoft_graph",
            tenant_id=self._TENANT,
            event_type="defender.security_signal",
        )
        assert isinstance(envelope.payload, DefenderSecuritySignalEvent)

    def test_risky_user_envelope_payload_provider_event_type(self) -> None:
        envelope = build_envelope(
            raw_body={"occurred_at": "2026-04-28T00:00:00Z"},
            normalized=self._normalized_risky_user(),
            provider="microsoft_graph",
            tenant_id=self._TENANT,
            event_type="defender.security_signal",
        )
        assert envelope.payload.provider_event_type == "risky_user"


# ---------------------------------------------------------------------------
# Seam 4: Route resolution via registry.resolve() with real Envelope objects
# ---------------------------------------------------------------------------


class TestRouteResolutionForSecuritySignals:
    """End-to-end predicate-based route resolution using built Envelopes."""

    _TENANT = "tenant-demo-001"

    def _make_envelope(self, *, provider_event_type: str) -> object:
        from shared.models.canonical import (
            Correlation,
            DefenderSecuritySignalEvent,
            Envelope,
            StoragePartition,
        )

        correlation = Correlation(
            correlation_id="corr-reg-1",
            causation_id="corr-reg-1",
            request_id="req-reg-1",
            trace_id="trace-reg-1",
            storage_partition=StoragePartition(
                ddb_pk=f"TENANT#{self._TENANT}",
                ddb_sk=f"EVENT#defender.security_signal#sig-1",
                s3_bucket=f"secamo-events-{self._TENANT}",
                s3_key_prefix="raw/defender.security_signal/sig-1",
            ),
        )
        return Envelope(
            event_id=f"evt-{provider_event_type}",
            tenant_id=self._TENANT,
            source_provider="microsoft_graph",
            event_name="defender.security_signal",
            schema_version="1.0.0",
            event_version="1.0.0",
            ocsf_version="1.1.0",
            occurred_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
            correlation=correlation,
            payload=DefenderSecuritySignalEvent(
                event_type="defender.security_signal",
                activity_id=5001 if provider_event_type == "signin_log" else 5002,
                activity_name=provider_event_type,
                signal_id="sig-1",
                provider_event_type=provider_event_type,
                resource_type=provider_event_type,
                title="Test signal",
                severity_id=40,
                severity="medium",
            ),
        )

    def test_signin_log_envelope_resolves_to_signin_anomaly_workflow(self) -> None:
        registry = build_default_route_registry()
        envelope = self._make_envelope(provider_event_type="signin_log")
        routes = registry.resolve(envelope)
        assert len(routes) == 1
        assert routes[0].workflow_name == "SigninAnomalyDetectionWorkflow"
        assert routes[0].task_queue == "edr"

    def test_risky_user_envelope_resolves_to_risky_user_triage_workflow(self) -> None:
        registry = build_default_route_registry()
        envelope = self._make_envelope(provider_event_type="risky_user")
        routes = registry.resolve(envelope)
        assert len(routes) == 1
        assert routes[0].workflow_name == "RiskyUserTriageWorkflow"
        assert routes[0].task_queue == "edr"

    def test_defender_alert_envelope_resolves_to_soc_triage_workflow(self) -> None:
        """Defender alert path must remain unchanged by the security-signal fix."""
        from shared.models.canonical import (
            Correlation,
            DefenderDetectionFindingEvent,
            Envelope,
            StoragePartition,
            VendorExtension,
        )

        correlation = Correlation(
            correlation_id="corr-alert-1",
            causation_id="corr-alert-1",
            request_id="req-alert-1",
            trace_id="trace-alert-1",
            storage_partition=StoragePartition(
                ddb_pk=f"TENANT#{self._TENANT}",
                ddb_sk="EVENT#defender.alert#alert-1",
                s3_bucket=f"secamo-events-{self._TENANT}",
                s3_key_prefix="raw/defender.alert/alert-1",
            ),
        )
        envelope = Envelope(
            event_id="evt-alert-1",
            tenant_id=self._TENANT,
            source_provider="microsoft_graph",
            event_name="defender.alert",
            schema_version="1.0.0",
            event_version="1.0.0",
            ocsf_version="1.1.0",
            occurred_at=datetime(2026, 4, 28, tzinfo=timezone.utc),
            correlation=correlation,
            payload=DefenderDetectionFindingEvent(
                event_type="defender.alert",
                activity_id=2004,
                alert_id="alert-1",
                title="Suspicious alert",
                severity_id=40,
                severity="medium",
            ),
        )
        registry = build_default_route_registry()
        routes = registry.resolve(envelope)
        assert len(routes) >= 1
        assert routes[0].workflow_name == "SocAlertTriageWorkflow"
