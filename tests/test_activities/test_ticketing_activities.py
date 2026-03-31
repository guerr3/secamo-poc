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
    provider = mocker.AsyncMock()
    provider.create_ticket.return_value = mocker.Mock(ticket_id="SOC-1")
    mocker.patch("activities.ticketing._get_ticketing_provider", return_value=provider)
    res = await ticket_create("t1", "jira", ticket_data)
    assert res.ticket_id == "SOC-1"
    provider.create_ticket.assert_awaited_once_with(ticket_data)


@pytest.mark.asyncio
async def test_ticket_update(mocker):
    provider = mocker.AsyncMock()
    provider.update_ticket.return_value = mocker.Mock(status="in_progress")
    mocker.patch("activities.ticketing._get_ticketing_provider", return_value=provider)
    res = await ticket_update("t1", "jira", "SOC-1", {"status": "in_progress"})
    assert res.status == "in_progress"
    provider.update_ticket.assert_awaited_once_with("SOC-1", {"status": "in_progress"})


@pytest.mark.asyncio
async def test_ticket_close(mocker):
    provider = mocker.AsyncMock()
    provider.close_ticket.return_value = mocker.Mock(status="closed")
    mocker.patch("activities.ticketing._get_ticketing_provider", return_value=provider)
    res = await ticket_close("t1", "jira", "SOC-1", "resolved")
    assert res.status == "closed"
    provider.close_ticket.assert_awaited_once_with("SOC-1", "resolved")


@pytest.mark.asyncio
async def test_ticket_get_details(mocker):
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
    provider = mocker.AsyncMock()
    provider.get_ticket_details.return_value = {"ticket_id": "SOC-1", **details}
    mocker.patch("activities.ticketing._get_ticketing_provider", return_value=provider)
    res = await ticket_get_details("t1", "jira", "SOC-1")
    assert res["ticket_id"] == "SOC-1"
    provider.get_ticket_details.assert_awaited_once_with("SOC-1")
