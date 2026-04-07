from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from shared.models.canonical import (
    Correlation,
    CustomerOnboardingEvent,
    StoragePartition,
    SecamoEventVariantAdapter,
)
from shared.models.mappers import build_envelope


def _sample_payload_dict() -> dict:
    return {
        "event_type": "customer.onboarding",
        "activity_id": 1,
        "activity_name": "create",
        "tenant_id": "tenant-demo-001",
        "display_name": "Demo Tenant",
        "config": {
            "display_name": "Demo Tenant",
            "ticketing_provider": "jira",
            "graph_subscriptions": "security/alerts_v2:created+updated:false:24",
        },
        "secrets": {
            "graph": {
                "client_id": "graph-client",
                "client_secret": "graph-secret",
                "tenant_azure_id": "azure-tenant",
            }
        },
        "welcome_email": "owner@example.com",
    }


def test_customer_onboarding_variant_adapter_accepts_payload() -> None:
    event = SecamoEventVariantAdapter.validate_python(_sample_payload_dict())

    assert isinstance(event, CustomerOnboardingEvent)
    assert event.event_type == "customer.onboarding"
    assert event.class_uid == 3003


def test_customer_onboarding_forbids_unknown_fields() -> None:
    payload = _sample_payload_dict()
    payload["unknown_field"] = True

    with pytest.raises(ValidationError):
        CustomerOnboardingEvent.model_validate(payload)


def test_build_envelope_accepts_customer_onboarding_payload() -> None:
    payload = CustomerOnboardingEvent.model_validate(_sample_payload_dict())

    envelope = build_envelope(
        tenant_id="tenant-demo-001",
        source_provider="internal-api",
        occurred_at=datetime(2026, 4, 7, tzinfo=timezone.utc),
        payload=payload,
        correlation=Correlation(
            correlation_id="corr-1",
            causation_id="corr-1",
            request_id="req-1",
            trace_id="trace-1",
            storage_partition=StoragePartition(
                ddb_pk="TENANT#tenant-demo-001",
                ddb_sk="EVENT#customer#onboarding#evt-1",
                s3_bucket="secamo-events-tenant-demo-001",
                s3_key_prefix="raw/customer.onboarding/evt-1",
            ),
        ),
        provider_event_id="evt-1",
    )

    assert envelope.payload.event_type == "customer.onboarding"
    assert envelope.tenant_id == "tenant-demo-001"
