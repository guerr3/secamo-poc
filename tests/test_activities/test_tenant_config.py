from __future__ import annotations

import pytest
from temporalio import activity
from temporalio.testing import ActivityEnvironment

from activities.tenant import get_tenant_config
from shared.models import TenantConfig


@activity.defn
async def mock_get_tenant_config(tenant_id: str) -> TenantConfig:
    """Test stub that avoids SSM and returns defaults."""
    return TenantConfig(tenant_id=tenant_id, display_name="Mock Tenant")


class _FakeSsmClient:
    def get_parameters_by_path(self, Path: str, WithDecryption: bool) -> dict:
        return {"Parameters": []}


class _FakeSsmClientWithPolling:
    def get_parameters_by_path(self, Path: str, WithDecryption: bool) -> dict:
        return {
            "Parameters": [
                {
                    "Name": f"{Path}polling_providers",
                    "Value": "microsoft_defender:defender_alerts:graph:300,jira:tickets:ticketing:120",
                }
            ]
        }


@pytest.mark.asyncio
async def test_get_tenant_config_defaults_without_ssm(monkeypatch: pytest.MonkeyPatch) -> None:
    from activities import tenant as tenant_module

    monkeypatch.setattr(tenant_module, "ssm_client", _FakeSsmClient())
    env = ActivityEnvironment()

    cfg: TenantConfig = await env.run(get_tenant_config, "tenant-demo-001")

    assert cfg.tenant_id == "tenant-demo-001"
    assert cfg.display_name == "Demo Klant BV"
    assert cfg.edr_provider == "microsoft_defender"
    assert cfg.ticketing_provider == "jira"
    assert cfg.threat_intel_providers == ["virustotal"]
    assert cfg.hitl_timeout_hours == 4
    assert cfg.max_activity_attempts == 3


@pytest.mark.asyncio
async def test_mock_get_tenant_config_stub() -> None:
    env = ActivityEnvironment()
    cfg: TenantConfig = await env.run(mock_get_tenant_config, "tenant-test-001")

    assert cfg.tenant_id == "tenant-test-001"
    assert cfg.display_name == "Mock Tenant"
    assert cfg.notification_provider == "teams"


@pytest.mark.asyncio
async def test_get_tenant_config_parses_polling_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    from activities import tenant as tenant_module

    monkeypatch.setattr(tenant_module, "ssm_client", _FakeSsmClientWithPolling())
    env = ActivityEnvironment()

    cfg: TenantConfig = await env.run(get_tenant_config, "tenant-demo-001")

    assert len(cfg.polling_providers) == 2
    assert cfg.polling_providers[0].provider == "microsoft_defender"
    assert cfg.polling_providers[0].resource_type == "defender_alerts"
    assert cfg.polling_providers[0].secret_type == "graph"
    assert cfg.polling_providers[0].poll_interval_seconds == 300
    assert cfg.polling_providers[1].provider == "jira"
    assert cfg.polling_providers[1].resource_type == "tickets"
    assert cfg.polling_providers[1].secret_type == "ticketing"
    assert cfg.polling_providers[1].poll_interval_seconds == 120
