from __future__ import annotations

import pytest

from connectors.registry import get_connector
from shared.models import TenantSecrets


@pytest.fixture
def secrets() -> TenantSecrets:
    return TenantSecrets(
        tenant_azure_id="tenant-1",
        client_id="client-id",
        client_secret="client-secret",
    )


STUB_PROVIDERS = [
    "crowdstrike",
    "sentinelone",
    "halo_itsm",
    "servicenow",
    "virustotal",
    "abuseipdb",
    "misp",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", STUB_PROVIDERS)
async def test_stub_connectors_health_and_fetch(provider: str, secrets: TenantSecrets):
    connector = get_connector(provider=provider, tenant_id="tenant-1", secrets=secrets)

    health = await connector.health_check()
    assert health["healthy"] is True
    assert health["provider"] == provider

    events = await connector.fetch_events({"top": 2})
    assert len(events) == 2
    assert all(event.source_provider == provider for event in events)


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", STUB_PROVIDERS)
async def test_stub_connectors_ticket_actions(provider: str, secrets: TenantSecrets):
    connector = get_connector(provider=provider, tenant_id="tenant-1", secrets=secrets)

    created = await connector.execute_action(
        "create_issue",
        {
            "project_key": "SOC",
            "title": "Stub ticket",
            "description": "Testing",
        },
    )
    assert created["success"] is True
    assert created["ticket_id"].startswith("SOC-")

    updated = await connector.execute_action(
        "update_issue",
        {
            "ticket_id": created["ticket_id"],
            "fields": {"status": "in_progress"},
        },
    )
    assert updated["success"] is True
    assert updated["updated"] is True

    closed = await connector.execute_action(
        "close_issue",
        {
            "ticket_id": created["ticket_id"],
            "transition_name": "Done",
        },
    )
    assert closed["success"] is True
    assert closed["closed"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", STUB_PROVIDERS)
async def test_stub_connectors_threat_intel_action(provider: str, secrets: TenantSecrets):
    connector = get_connector(provider=provider, tenant_id="tenant-1", secrets=secrets)

    benign = await connector.execute_action("lookup_indicator", {"indicator": "example.com"})
    assert benign["success"] is True
    assert benign["is_malicious"] is False

    malicious = await connector.execute_action("lookup_indicator", {"indicator": "bad-ransom.example"})
    assert malicious["success"] is True
    assert malicious["is_malicious"] is True
