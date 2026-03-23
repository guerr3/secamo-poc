from __future__ import annotations

import importlib
import sys
import types

from fastapi import APIRouter
from fastapi.testclient import TestClient


def _build_client() -> TestClient:
    stub_module = types.ModuleType("graph_ingress.chatops_webhook")
    stub_module.router = APIRouter()
    sys.modules["graph_ingress.chatops_webhook"] = stub_module

    app_module = importlib.import_module("graph_ingress.app")
    app_module = importlib.reload(app_module)
    return TestClient(app_module.app)


def test_post_validation_token_returns_plain_text() -> None:
    client = _build_client()

    response = client.post(
        "/graph/notifications?validationToken=opaque-token-123",
        data="not-json",
        headers={"content-type": "text/plain"},
    )

    assert response.status_code == 200
    assert response.text == "opaque-token-123"
    assert response.headers["content-type"].startswith("text/plain")


def test_get_validation_token_still_supported() -> None:
    client = _build_client()

    response = client.get("/graph/notifications?validationToken=opaque-token-123")

    assert response.status_code == 200
    assert response.text == "opaque-token-123"
