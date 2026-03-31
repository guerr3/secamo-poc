from __future__ import annotations

import pytest

from shared.graph_client import clear_token_cache, get_defender_token, get_graph_token
from shared.providers.contracts import TenantSecrets


class _Resp:
    def __init__(self, status: int, body: dict | None = None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


class _Client:
    def __init__(self, responses: list[_Resp], calls: list[dict]):
        self._responses = responses
        self._calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url: str, data: dict):
        self._calls.append({"url": url, "data": dict(data)})
        return self._responses.pop(0)


@pytest.fixture
def secrets() -> TenantSecrets:
    return TenantSecrets(
        client_id="client-id",
        client_secret="super-secret-value",
        tenant_azure_id="tenant-1",
    )


@pytest.fixture(autouse=True)
def _clear_cache_each_test():
    clear_token_cache()
    yield
    clear_token_cache()


@pytest.mark.asyncio
async def test_cache_miss_fetches_token(mocker, secrets):
    calls: list[dict] = []
    mocker.patch(
        "shared.graph_client.httpx.AsyncClient",
        return_value=_Client([_Resp(200, {"access_token": "g1", "expires_in": 3600})], calls),
    )

    token = await get_graph_token(secrets)

    assert token == "g1"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_cache_hit_skips_http(mocker, secrets):
    calls: list[dict] = []
    mocker.patch(
        "shared.graph_client.httpx.AsyncClient",
        return_value=_Client([_Resp(200, {"access_token": "g1", "expires_in": 3600})], calls),
    )

    first = await get_graph_token(secrets)
    second = await get_graph_token(secrets)

    assert first == "g1"
    assert second == "g1"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_expired_token_refreshes(mocker, secrets):
    calls: list[dict] = []
    mocker.patch(
        "shared.graph_client.httpx.AsyncClient",
        return_value=_Client(
            [
                _Resp(200, {"access_token": "g1", "expires_in": 1}),
                _Resp(200, {"access_token": "g2", "expires_in": 3600}),
            ],
            calls,
        ),
    )

    t1 = await get_graph_token(secrets)
    t2 = await get_graph_token(secrets)

    assert t1 == "g1"
    assert t2 == "g2"
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_graph_and_defender_cache_independent(mocker, secrets):
    calls: list[dict] = []
    mocker.patch(
        "shared.graph_client.httpx.AsyncClient",
        return_value=_Client(
            [
                _Resp(200, {"access_token": "graph-token", "expires_in": 3600}),
                _Resp(200, {"access_token": "def-token", "expires_in": 3600}),
            ],
            calls,
        ),
    )

    g1 = await get_graph_token(secrets)
    d1 = await get_defender_token(secrets)
    g2 = await get_graph_token(secrets)
    d2 = await get_defender_token(secrets)

    assert g1 == "graph-token"
    assert d1 == "def-token"
    assert g2 == "graph-token"
    assert d2 == "def-token"
    assert len(calls) == 2
    assert calls[0]["data"]["scope"] == "https://graph.microsoft.com/.default"
    assert calls[1]["data"]["scope"] == "https://api.securitycenter.microsoft.com/.default"


@pytest.mark.asyncio
async def test_failed_fetch_raises_without_secret_leak(mocker, secrets):
    calls: list[dict] = []
    mocker.patch(
        "shared.graph_client.httpx.AsyncClient",
        return_value=_Client([_Resp(401, {"error": "invalid_client"})], calls),
    )

    with pytest.raises(RuntimeError) as exc:
        await get_graph_token(secrets)

    assert "super-secret-value" not in str(exc.value)
    assert "401" in str(exc.value)
