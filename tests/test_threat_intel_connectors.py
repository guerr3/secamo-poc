from __future__ import annotations

from typing import Any

import pytest

from connectors.abuseipdb import AbuseIpdbConnector
from connectors.errors import ConnectorPermanentError
from connectors.virustotal import VirusTotalConnector
from shared.providers.contracts import TenantSecrets


class _Resp:
    def __init__(
        self,
        status: int,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}

    def json(self) -> dict[str, Any]:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"status={self.status_code}")


class _Client:
    def __init__(self, queue: list[_Resp], calls: list[dict[str, Any]]):
        self._queue = queue
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method: str, url: str, **kwargs):
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._queue.pop(0)


@pytest.fixture
def tenant_secrets() -> TenantSecrets:
    return TenantSecrets(
        tenant_azure_id="tenant-1",
        client_id="client-id",
        client_secret="client-secret",
        virustotal_api_key="vt-key",
        abuseipdb_api_key="abuse-key",
    )


@pytest.mark.asyncio
async def test_virustotal_lookup_indicator_parses_score(mocker, tenant_secrets):
    queue = [
        _Resp(
            200,
            body={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                            "harmless": 3,
                            "undetected": 4,
                        }
                    }
                }
            },
        )
    ]
    calls: list[dict[str, Any]] = []
    mocker.patch(
        "connectors.virustotal.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = VirusTotalConnector(tenant_id="tenant-1", secrets=tenant_secrets)
    result = await connector.execute_action("lookup_indicator", {"indicator": "8.8.8.8"})

    assert result["provider"] == "virustotal"
    assert result["is_malicious"] is True
    assert result["reputation_score"] == 30.0
    assert calls[0]["headers"]["x-apikey"] == "vt-key"


@pytest.mark.asyncio
async def test_virustotal_lookup_indicator_not_found_returns_benign(mocker, tenant_secrets):
    queue = [_Resp(404, body={})]
    calls: list[dict[str, Any]] = []
    mocker.patch(
        "connectors.virustotal.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = VirusTotalConnector(tenant_id="tenant-1", secrets=tenant_secrets)
    result = await connector.execute_action("lookup_indicator", {"indicator": "unknown.example"})

    assert result["is_malicious"] is False
    assert result["reputation_score"] == 0.0
    assert result["details"] == "indicator not found"


@pytest.mark.asyncio
async def test_abuseipdb_lookup_indicator_parses_confidence_score(mocker, tenant_secrets):
    queue = [
        _Resp(
            200,
            body={
                "data": {
                    "abuseConfidenceScore": 87,
                    "totalReports": 120,
                    "countryCode": "NL",
                }
            },
        )
    ]
    calls: list[dict[str, Any]] = []
    mocker.patch(
        "connectors.abuseipdb.httpx.AsyncClient",
        side_effect=lambda **kwargs: _Client(queue, calls),
    )

    connector = AbuseIpdbConnector(tenant_id="tenant-1", secrets=tenant_secrets)
    result = await connector.execute_action("lookup_indicator", {"indicator": "1.1.1.1"})

    assert result["provider"] == "abuseipdb"
    assert result["is_malicious"] is True
    assert result["reputation_score"] == 87.0
    assert calls[0]["headers"]["Key"] == "abuse-key"


@pytest.mark.asyncio
async def test_abuseipdb_lookup_rejects_non_ip_indicator(tenant_secrets):
    connector = AbuseIpdbConnector(tenant_id="tenant-1", secrets=tenant_secrets)

    with pytest.raises(ConnectorPermanentError, match="IP indicators only"):
        await connector.execute_action("lookup_indicator", {"indicator": "evil.example"})
