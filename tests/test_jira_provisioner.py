from __future__ import annotations

import pytest

from connectors.jira_provisioner import JiraProvisioner
from shared.providers.contracts import TenantSecrets


@pytest.fixture
def jsm_secrets() -> TenantSecrets:
    return TenantSecrets(
        tenant_azure_id="tenant-1",
        client_id="client-id",
        client_secret="client-secret",
        jira_base_url="https://jira.example.com",
        jira_email="user@example.com",
        jira_api_token="token",
        project_key="SOC",
        project_type="jsm",
    )


@pytest.mark.asyncio
async def test_provision_jsm_tenant_skips_standard_project_type(mocker, jsm_secrets: TenantSecrets) -> None:
    provisioner = JiraProvisioner()
    ensure_secret = mocker.patch.object(provisioner, "_ensure_secret_value")

    result = await provisioner.provision_jsm_tenant(
        "tenant-1",
        jsm_secrets.model_copy(update={"project_type": "standard"}),
    )

    assert result.project_type == "standard"
    ensure_secret.assert_not_called()


@pytest.mark.asyncio
async def test_provision_jsm_tenant_discovers_and_persists_service_desk(mocker, jsm_secrets: TenantSecrets) -> None:
    provisioner = JiraProvisioner()

    mocker.patch.object(provisioner, "_resolve_callback_base_url", return_value="https://api.example.com")
    mocker.patch.object(provisioner, "_ensure_secret_value", side_effect=["ingress-secret", "hitl-secret"])
    ensure_webhook = mocker.patch.object(provisioner, "_ensure_webhook", new=mocker.AsyncMock())
    discover_service_desk = mocker.patch.object(
        provisioner,
        "_discover_service_desk_id",
        new=mocker.AsyncMock(return_value="42"),
    )
    persist_fields = mocker.patch.object(provisioner, "_persist_ticketing_fields")

    result = await provisioner.provision_jsm_tenant("tenant-1", jsm_secrets)

    assert result.project_type == "jsm"
    assert result.jsm_service_desk_id == "42"
    assert ensure_webhook.await_count == 2
    discover_service_desk.assert_awaited_once()
    persist_fields.assert_called_once_with(
        "tenant-1",
        {
            "project_type": "jsm",
            "jsm_service_desk_id": "42",
        },
    )


@pytest.mark.asyncio
async def test_provision_jsm_tenant_uses_existing_service_desk(mocker, jsm_secrets: TenantSecrets) -> None:
    provisioner = JiraProvisioner()
    tenant_secrets = jsm_secrets.model_copy(update={"jsm_service_desk_id": "99"})

    mocker.patch.object(provisioner, "_resolve_callback_base_url", return_value="https://api.example.com")
    mocker.patch.object(provisioner, "_ensure_secret_value", side_effect=["ingress-secret", "hitl-secret"])
    ensure_webhook = mocker.patch.object(provisioner, "_ensure_webhook", new=mocker.AsyncMock())
    discover_service_desk = mocker.patch.object(provisioner, "_discover_service_desk_id", new=mocker.AsyncMock())
    persist_fields = mocker.patch.object(provisioner, "_persist_ticketing_fields")

    result = await provisioner.provision_jsm_tenant("tenant-1", tenant_secrets)

    assert result.jsm_service_desk_id == "99"
    assert ensure_webhook.await_count == 2
    discover_service_desk.assert_not_awaited()
    persist_fields.assert_called_once_with(
        "tenant-1",
        {
            "project_type": "jsm",
            "jsm_service_desk_id": "99",
        },
    )
