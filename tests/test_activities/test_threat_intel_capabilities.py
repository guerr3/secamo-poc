from __future__ import annotations

import pytest

from activities.threat_intel import threat_intel_fanout
from shared.models import ThreatIntelResult


@pytest.mark.asyncio
async def test_threat_intel_fanout_selects_highest_reputation(mocker):
    provider = mocker.AsyncMock()
    provider.fanout.return_value = ThreatIntelResult(
        indicator="1.2.3.4",
        provider="abuseipdb",
        is_malicious=True,
        reputation_score=87.0,
        details="high confidence malicious",
    )
    get_provider = mocker.patch("activities.threat_intel._get_provider", return_value=provider)

    result = await threat_intel_fanout("tenant-1", ["virustotal", "abuseipdb"], "1.2.3.4")

    assert result.provider == "abuseipdb"
    assert result.is_malicious is True
    assert result.reputation_score == 87.0
    get_provider.assert_awaited_once_with("tenant-1", default_provider="virustotal")
    provider.fanout.assert_awaited_once_with("1.2.3.4", ["virustotal", "abuseipdb"])


@pytest.mark.asyncio
async def test_threat_intel_fanout_returns_default_when_all_fail(mocker):
    provider = mocker.AsyncMock()
    provider.fanout.return_value = ThreatIntelResult(
        indicator="8.8.8.8",
        provider="none",
        is_malicious=False,
        reputation_score=0.0,
        details="No provider returned a positive result.",
    )
    mocker.patch("activities.threat_intel._get_provider", return_value=provider)

    result = await threat_intel_fanout("tenant-1", ["virustotal"], "8.8.8.8")

    assert result.provider == "none"
    assert result.is_malicious is False
    assert result.reputation_score == 0.0
