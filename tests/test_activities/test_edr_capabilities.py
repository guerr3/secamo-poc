from __future__ import annotations

import pytest
from temporalio.exceptions import ApplicationError

from activities.edr import edr_fetch_events
from connectors.errors import ConnectorTransientError


@pytest.mark.asyncio
async def test_edr_fetch_events_uses_provider_override(mocker):
    provider = mocker.AsyncMock()
    provider.fetch_events.return_value = []
    get_provider = mocker.patch("activities.edr._get_provider", return_value=provider)

    result = await edr_fetch_events(
        "tenant-1",
        {"provider": "crowdstrike", "resource_type": "defender_alerts", "top": 100},
    )

    assert result.success is True
    assert result.provider == "crowdstrike"
    assert result.data.raw_count == 0
    get_provider.assert_awaited_once_with("tenant-1", provider_override="crowdstrike")
    provider.fetch_events.assert_awaited_once()


@pytest.mark.asyncio
async def test_edr_fetch_events_transient_error_is_retryable(mocker):
    provider = mocker.AsyncMock()
    provider.fetch_events.side_effect = ConnectorTransientError("temporary 503")
    mocker.patch("activities.edr._get_provider", return_value=provider)

    with pytest.raises(ApplicationError) as exc:
        await edr_fetch_events("tenant-1", {"provider": "microsoft_defender"})

    assert exc.value.type == "ConnectorTransientError"
    assert exc.value.non_retryable is False
