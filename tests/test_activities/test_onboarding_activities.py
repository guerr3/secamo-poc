from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.onboarding import provision_customer_secrets, register_customer_tenant
from shared.models.canonical import CustomerOnboardingEvent


def _payload(**updates) -> CustomerOnboardingEvent:
    data = {
        "event_type": "customer.onboarding",
        "activity_id": 1,
        "activity_name": "create",
        "tenant_id": "tenant-1",
        "display_name": "Tenant One",
        "config": {
            "display_name": "Tenant One",
            "sla_tier": "standard",
            "soc_analyst_email": "analyst@example.com",
        },
        "secrets": {
            "graph": {
                "client_id": "graph-client",
                "client_secret": "graph-secret",
                "tenant_azure_id": "azure-tenant",
                "teams_webhook_url": "https://teams.example/webhook",
            },
            "ticketing": {
                "jira_base_url": "https://example.atlassian.net",
                "jira_email": "jira@example.com",
                "jira_api_token": "jira-token",
            },
        },
        "welcome_email": "owner@example.com",
    }
    data.update(updates)
    return CustomerOnboardingEvent.model_validate(data)


@pytest.mark.asyncio
async def test_provision_customer_secrets_writes_expected_paths(mocker) -> None:
    put_secret = mocker.patch("activities.onboarding.put_secret")
    mocker.patch("activities.onboarding._resolve_callback_base_url", return_value="https://secamo.example")

    result = await provision_customer_secrets("tenant-1", _payload())

    assert result["graph_notification_url"] == "https://secamo.example/api/v1/graph/notifications/tenant-1"
    called_paths = {call.kwargs["path"] for call in put_secret.call_args_list}
    assert "config/display_name" in called_paths
    assert "graph/client_id" in called_paths
    assert "graph/client_secret" in called_paths
    assert "graph/tenant_azure_id" in called_paths


@pytest.mark.asyncio
async def test_provision_customer_secrets_requires_graph_bundle() -> None:
    with pytest.raises(ApplicationError) as exc:
        await provision_customer_secrets(
            "tenant-1",
            _payload(secrets={}),
        )

    assert exc.value.type == "MissingGraphSecretBundle"
    assert exc.value.non_retryable is True


@pytest.mark.asyncio
async def test_register_customer_tenant_upserts_item(mocker, monkeypatch: pytest.MonkeyPatch) -> None:
    from activities import onboarding as onboarding_module

    table = mocker.Mock()
    table.put_item.return_value = {}
    dynamo = mocker.Mock()
    dynamo.Table.return_value = table

    monkeypatch.setattr(onboarding_module, "TENANT_TABLE_NAME", "tenant-table")
    mocker.patch("activities.onboarding._get_dynamodb_resource", return_value=dynamo)

    result = await register_customer_tenant("tenant-1", _payload())

    assert result["tenant_id"] == "tenant-1"
    assert result["display_name"] == "Tenant One"
    table.put_item.assert_called_once()


@pytest.mark.asyncio
async def test_register_customer_tenant_requires_table_name(monkeypatch: pytest.MonkeyPatch) -> None:
    from activities import onboarding as onboarding_module

    monkeypatch.setattr(onboarding_module, "TENANT_TABLE_NAME", "")

    with pytest.raises(ApplicationError) as exc:
        await register_customer_tenant("tenant-1", _payload())

    assert exc.value.type == "MissingTenantTableConfig"
    assert exc.value.non_retryable is True
