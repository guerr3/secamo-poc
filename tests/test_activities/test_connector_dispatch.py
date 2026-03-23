from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.connector_dispatch import connector_execute_action
from connectors.errors import ConnectorConfigurationError, ConnectorTransientError
from shared.models import TenantSecrets


@pytest.fixture
def secrets() -> TenantSecrets:
    return TenantSecrets(
        tenant_azure_id="tenant-1",
        client_id="client-id",
        client_secret="client-secret",
    )


@pytest.mark.asyncio
async def test_connector_execute_action_success(mocker, secrets):
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {"ticket_id": "SOC-1", "updated": True}
    mocker.patch("activities.connector_dispatch.get_connector", return_value=connector)

    result = await connector_execute_action(
        tenant_id="tenant-1",
        provider="jira",
        action="update_ticket",
        payload={"ticket_id": "SOC-1", "fields": {"status": "done"}},
        secrets=secrets,
    )

    assert result.success is True
    assert result.data["ticket_id"] == "SOC-1"


@pytest.mark.asyncio
async def test_connector_execute_action_reported_failure_raises_non_retryable(mocker, secrets):
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {
        "success": False,
        "reason": "provider not implemented",
    }
    mocker.patch("activities.connector_dispatch.get_connector", return_value=connector)

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="crowdstrike",
            action="lookup_indicator",
            payload={"indicator": "1.2.3.4"},
            secrets=secrets,
        )

    assert exc.value.non_retryable is True
    assert exc.value.type == "ConnectorActionReportedFailure"


@pytest.mark.asyncio
async def test_connector_execute_action_reported_failure_can_be_retryable(mocker, secrets):
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {
        "success": False,
        "reason": "provider unavailable",
        "retryable": True,
    }
    mocker.patch("activities.connector_dispatch.get_connector", return_value=connector)

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="jira",
            action="create_ticket",
            payload={"title": "x"},
            secrets=secrets,
        )

    assert exc.value.non_retryable is False
    assert exc.value.type == "ConnectorActionReportedFailure"


@pytest.mark.asyncio
async def test_connector_execute_action_unknown_provider_non_retryable(mocker, secrets):
    mocker.patch(
        "activities.connector_dispatch.get_connector",
        side_effect=ConnectorConfigurationError("unknown provider"),
    )

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="unknown",
            action="create_ticket",
            payload={"title": "x"},
            secrets=secrets,
        )

    assert exc.value.non_retryable is True
    assert exc.value.type == "ConnectorPermanentError"


@pytest.mark.asyncio
async def test_connector_execute_action_transient_error_retryable(mocker, secrets):
    connector = mocker.AsyncMock()
    connector.execute_action.side_effect = ConnectorTransientError("temporary 503")
    mocker.patch("activities.connector_dispatch.get_connector", return_value=connector)

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="jira",
            action="create_ticket",
            payload={"title": "x"},
            secrets=secrets,
        )

    assert exc.value.non_retryable is False
    assert exc.value.type == "ConnectorTransientError"
