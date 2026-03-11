from __future__ import annotations

import pytest

from activities.graph_users import (
    graph_assign_license,
    graph_create_user,
    graph_delete_user,
    graph_get_user,
    graph_reset_password,
    graph_revoke_sessions,
    graph_update_user,
)
from shared.models import TenantSecrets, UserData


class _Resp:
    def __init__(self, status: int, body: dict | None = None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


class _Client:
    def __init__(self, responses: dict[str, _Resp]):
        self.responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        return self.responses["get"]

    async def post(self, *args, **kwargs):
        return self.responses["post"]

    async def patch(self, *args, **kwargs):
        return self.responses["patch"]

    async def delete(self, *args, **kwargs):
        return self.responses["delete"]


@pytest.fixture
def secrets() -> TenantSecrets:
    return TenantSecrets(client_id="cid", client_secret="csec", tenant_azure_id="tid")


@pytest.fixture
def user_data() -> UserData:
    return UserData(
        email="john@example.com",
        first_name="John",
        last_name="Doe",
        department="Engineering",
        role="Developer",
    )


@pytest.mark.asyncio
async def test_graph_get_user_happy(mocker, secrets):
    mocker.patch("activities.graph_users.get_graph_token", return_value="tok")
    mocker.patch(
        "activities.graph_users.httpx.AsyncClient",
        return_value=_Client({"get": _Resp(200, {"id": "u1", "displayName": "John", "mail": "john@example.com", "accountEnabled": True})}),
    )
    user = await graph_get_user("t1", "john@example.com", secrets)
    assert user is not None
    assert user.user_id == "u1"


@pytest.mark.asyncio
async def test_graph_get_user_404(mocker, secrets):
    mocker.patch("activities.graph_users.get_graph_token", return_value="tok")
    mocker.patch("activities.graph_users.httpx.AsyncClient", return_value=_Client({"get": _Resp(404)}))
    assert await graph_get_user("t1", "none@example.com", secrets) is None


@pytest.mark.asyncio
async def test_graph_create_user_happy(mocker, secrets, user_data):
    mocker.patch("activities.graph_users.get_graph_token", return_value="tok")
    mocker.patch(
        "activities.graph_users.httpx.AsyncClient",
        return_value=_Client({"post": _Resp(201, {"id": "u2", "displayName": "John Doe", "userPrincipalName": user_data.email, "accountEnabled": True})}),
    )
    created = await graph_create_user("t1", user_data, secrets)
    assert created.user_id == "u2"


@pytest.mark.asyncio
async def test_graph_update_user_happy(mocker, secrets):
    mocker.patch("activities.graph_users.get_graph_token", return_value="tok")
    mocker.patch("activities.graph_users.httpx.AsyncClient", return_value=_Client({"patch": _Resp(204)}))
    assert await graph_update_user("t1", "u1", {"department": "Finance"}, secrets) is True


@pytest.mark.asyncio
async def test_graph_delete_user_paths(mocker, secrets):
    mocker.patch("activities.graph_users.get_graph_token", return_value="tok")
    mocker.patch("activities.graph_users.httpx.AsyncClient", return_value=_Client({"delete": _Resp(404)}))
    assert await graph_delete_user("t1", "missing", secrets) is False


@pytest.mark.asyncio
async def test_graph_revoke_sessions_happy(mocker, secrets):
    mocker.patch("activities.graph_users.get_graph_token", return_value="tok")
    mocker.patch("activities.graph_users.httpx.AsyncClient", return_value=_Client({"post": _Resp(200)}))
    assert await graph_revoke_sessions("t1", "u1", secrets) is True


@pytest.mark.asyncio
async def test_graph_assign_and_reset_password_happy(mocker, secrets):
    mocker.patch("activities.graph_users.get_graph_token", return_value="tok")
    mocker.patch("activities.graph_users.httpx.AsyncClient", return_value=_Client({"post": _Resp(200), "patch": _Resp(204)}))
    assert await graph_assign_license("t1", "u1", "sku", secrets) is True
    assert await graph_reset_password("t1", "u1", "TempP@ss1234", secrets) is True
