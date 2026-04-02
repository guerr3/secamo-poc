from __future__ import annotations

import pytest

from activities.threat_intel import threat_intel_fanout


@pytest.mark.asyncio
async def test_threat_intel_fanout_selects_highest_reputation(mocker):
    virustotal = mocker.AsyncMock()
    virustotal.execute_action.return_value = {
        "reputation_score": 12,
        "is_malicious": False,
        "details": "clean",
    }
    abuseipdb = mocker.AsyncMock()
    abuseipdb.execute_action.return_value = {
        "reputation_score": 87,
        "is_malicious": True,
        "details": "high confidence malicious",
    }

    connectors = {
        "virustotal": virustotal,
        "abuseipdb": abuseipdb,
    }

    mocker.patch("activities.threat_intel.secret_type_for_provider", return_value="threatintel")
    mocker.patch("activities.threat_intel.load_tenant_secrets", return_value={"api_key": "x"})

    def _get_connector(*, provider: str, tenant_id: str, secrets: dict):
        assert tenant_id == "tenant-1"
        assert secrets == {"api_key": "x"}
        return connectors[provider]

    mocker.patch("activities.threat_intel.get_connector", side_effect=_get_connector)

    result = await threat_intel_fanout("tenant-1", ["virustotal", "abuseipdb"], "1.2.3.4")

    assert result.provider == "abuseipdb"
    assert result.is_malicious is True
    assert result.reputation_score == 87.0
    virustotal.execute_action.assert_awaited_once_with("lookup_indicator", {"indicator": "1.2.3.4"})
    abuseipdb.execute_action.assert_awaited_once_with("lookup_indicator", {"indicator": "1.2.3.4"})


@pytest.mark.asyncio
async def test_threat_intel_fanout_returns_default_when_all_fail(mocker):
    failing_connector = mocker.AsyncMock()
    failing_connector.execute_action.side_effect = RuntimeError("provider unavailable")

    mocker.patch("activities.threat_intel.secret_type_for_provider", return_value="threatintel")
    mocker.patch("activities.threat_intel.load_tenant_secrets", return_value={"api_key": "x"})
    mocker.patch("activities.threat_intel.get_connector", return_value=failing_connector)

    result = await threat_intel_fanout("tenant-1", ["virustotal"], "8.8.8.8")

    assert result.provider == "none"
    assert result.is_malicious is False
    assert result.reputation_score == 0.0
