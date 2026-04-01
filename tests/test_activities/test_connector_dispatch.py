from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.provider_capabilities import connector_execute_action
from connectors.errors import ConnectorTransientError


@pytest.mark.asyncio
async def test_connector_execute_action_success(mocker):
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {"ticket_id": "SOC-1", "updated": True}
    mocker.patch("activities.provider_capabilities._load_connector", return_value=connector)

    result = await connector_execute_action(
        tenant_id="tenant-1",
        provider="jira",
        action="update_ticket",
        payload={"ticket_id": "SOC-1", "fields": {"status": "done"}},
    )

    assert result.success is True
    assert result.data.payload["ticket_id"] == "SOC-1"


@pytest.mark.asyncio
async def test_connector_execute_action_reported_failure_raises_non_retryable(mocker):
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {
        "success": False,
        "reason": "provider not implemented",
    }
    mocker.patch("activities.provider_capabilities._load_connector", return_value=connector)

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="crowdstrike",
            action="lookup_indicator",
            payload={"indicator": "1.2.3.4"},
        )

    assert exc.value.non_retryable is True
    assert exc.value.type == "ConnectorActionReportedFailure"


@pytest.mark.asyncio
async def test_connector_execute_action_reported_failure_can_be_retryable(mocker):
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {
        "success": False,
        "reason": "provider unavailable",
        "retryable": True,
    }
    mocker.patch("activities.provider_capabilities._load_connector", return_value=connector)

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="jira",
            action="create_ticket",
            payload={"title": "x"},
        )

    assert exc.value.non_retryable is False
    assert exc.value.type == "ConnectorActionReportedFailure"


@pytest.mark.asyncio
async def test_connector_execute_action_unknown_provider_non_retryable(mocker):
    mocker.patch(
        "activities.provider_capabilities._load_connector",
        side_effect=ValueError("unknown provider"),
    )

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="unknown",
            action="create_ticket",
            payload={"title": "x"},
        )

    assert exc.value.non_retryable is False
    assert exc.value.type == "ConnectorActivityError"


@pytest.mark.asyncio
async def test_connector_execute_action_unknown_provider_fails_fast_before_connector_lookup(mocker):
    connector_lookup = mocker.patch("activities.provider_capabilities.get_connector")

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="unknown",
            action="create_ticket",
            payload={"title": "x"},
        )

    assert exc.value.non_retryable is False
    assert exc.value.type == "ConnectorActivityError"
    connector_lookup.assert_not_called()


@pytest.mark.asyncio
async def test_connector_execute_action_transient_error_retryable(mocker):
    connector = mocker.AsyncMock()
    connector.execute_action.side_effect = ConnectorTransientError("temporary 503")
    mocker.patch("activities.provider_capabilities._load_connector", return_value=connector)

    with pytest.raises(ApplicationError) as exc:
        await connector_execute_action(
            tenant_id="tenant-1",
            provider="jira",
            action="create_ticket",
            payload={"title": "x"},
        )

    assert exc.value.non_retryable is False
    assert exc.value.type == "ConnectorTransientError"
