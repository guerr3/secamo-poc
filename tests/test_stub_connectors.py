from __future__ import annotations

import pytest

from connectors.registry import get_connector
from shared.providers.contracts import TenantSecrets


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


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", STUB_PROVIDERS)
async def test_stub_connectors_soc_capability_actions(provider: str, secrets: TenantSecrets):
    connector = get_connector(provider=provider, tenant_id="tenant-1", secrets=secrets)

    device = await connector.execute_action("get_device_context", {"device_id": "dev-1"})
    assert device["success"] is True
    assert device["found"] is True
    assert device["device_id"] == "dev-1"

    identity = await connector.execute_action("get_identity_risk", {"lookup_key": "user@example.com"})
    assert identity["success"] is True
    assert identity["found"] is True
    assert identity["subject"] == "user@example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", STUB_PROVIDERS)
async def test_stub_connectors_phase1_action_aliases(provider: str, secrets: TenantSecrets):
    connector = get_connector(provider=provider, tenant_id="tenant-1", secrets=secrets)

    alerts = await connector.execute_action("list_user_alerts", {"user_email": "user@example.com"})
    risky = await connector.execute_action("list_risky_users", {"min_risk_level": "medium"})
    signins = await connector.execute_action("get_signin_history", {"user_principal_name": "user@example.com", "top": 5})
    confirmed = await connector.execute_action("confirm_user_compromised", {"user_id": "u-1"})
    dismissed = await connector.execute_action("dismiss_risky_user", {"user_id": "u-1"})
    scan = await connector.execute_action("run_antivirus_scan", {"device_id": "dev-1", "scan_type": "quick"})
    devices = await connector.execute_action("list_noncompliant_devices", {})
    unisolate = await connector.execute_action("unisolate_device", {"device_id": "dev-1"})

    assert alerts["success"] is True
    assert risky["success"] is True
    assert signins["success"] is True
    assert confirmed["success"] is True
    assert dismissed["success"] is True
    assert scan["success"] is True
    assert devices["success"] is True
    assert unisolate["success"] is True
