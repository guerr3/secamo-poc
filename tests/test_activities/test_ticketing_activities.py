from __future__ import annotations

import pytest

from activities.ticketing import ticket_close, ticket_create, ticket_get_details, ticket_update
from shared.models import TicketData


@pytest.fixture
def ticket_data() -> TicketData:
    return TicketData(
        tenant_id="t1",
        title="Alert",
        description="Desc",
        severity="high",
        source_workflow="WF-02",
    )


@pytest.mark.asyncio
async def test_ticket_create(mocker, ticket_data):
    mocker.patch("activities.ticketing.get_secret_bundle", return_value={"jira_base_url": "https://jira.example.com", "jira_email": "a@b", "jira_api_token": "t", "project_key": "SOC"})
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {"key": "SOC-1"}
    mocker.patch("activities.ticketing.get_connector", return_value=connector)
    res = await ticket_create("t1", "jira", ticket_data)
    assert res.ticket_id == "SOC-1"


@pytest.mark.asyncio
async def test_ticket_update(mocker):
    mocker.patch("activities.ticketing.get_secret_bundle", return_value={"jira_base_url": "https://jira.example.com", "jira_email": "a@b", "jira_api_token": "t"})
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {"ticket_id": "SOC-1", "updated": True}
    mocker.patch("activities.ticketing.get_connector", return_value=connector)
    res = await ticket_update("t1", "jira", "SOC-1", {"status": "in_progress"})
    assert res.status == "in_progress"


@pytest.mark.asyncio
async def test_ticket_close(mocker):
    mocker.patch("activities.ticketing.get_secret_bundle", return_value={"jira_base_url": "https://jira.example.com", "jira_email": "a@b", "jira_api_token": "t"})
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = {"closed": True}
    mocker.patch("activities.ticketing.get_connector", return_value=connector)
    res = await ticket_close("t1", "jira", "SOC-1", "resolved")
    connector.execute_action.assert_awaited_once_with(
        "close_issue",
        {
            "ticket_id": "SOC-1",
            "transition_name": "Done",
            "resolution": "resolved",
        },
    )
    assert res.status == "closed"


@pytest.mark.asyncio
async def test_ticket_get_details(mocker):
    mocker.patch("activities.ticketing.get_secret_bundle", return_value={"jira_base_url": "https://jira.example.com", "jira_email": "a@b", "jira_api_token": "t"})
    details = {
        "key": "SOC-1",
        "fields": {
            "summary": "Alert",
            "description": "Body",
            "priority": {"name": "High"},
            "status": {"name": "Open"},
            "assignee": {"emailAddress": "user@example.com"},
            "created": "2026-01-01T00:00:00Z",
        },
    }
    connector = mocker.AsyncMock()
    connector.execute_action.return_value = details
    mocker.patch("activities.ticketing.get_connector", return_value=connector)
    res = await ticket_get_details("t1", "jira", "SOC-1")
    assert res["ticket_id"] == "SOC-1"
