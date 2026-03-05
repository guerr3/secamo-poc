"""
ingress_sdk.response — Standardized API Gateway response helpers.

All helpers return a dict compatible with API Gateway proxy integration,
with consistent Content-Type headers and JSON-encoded bodies.
"""

import json
from typing import Any


_DEFAULT_HEADERS = {
    "Content-Type": "application/json",
}


def ok(data: Any = None, *, message: str = "ok") -> dict:
    """200 OK response."""
    body = data if data is not None else {"status": message}
    return {
        "statusCode": 200,
        "headers": {**_DEFAULT_HEADERS},
        "body": json.dumps(body),
    }


def accepted(data: Any = None, *, message: str = "accepted") -> dict:
    """202 Accepted response (for async workflow starts)."""
    body = data if data is not None else {"status": message}
    return {
        "statusCode": 202,
        "headers": {**_DEFAULT_HEADERS},
        "body": json.dumps(body),
    }


def error(status_code: int, message: str, *, details: Any = None) -> dict:
    """Error response with status code and message."""
    body: dict[str, Any] = {"error": message}
    if details is not None:
        body["details"] = details
    return {
        "statusCode": status_code,
        "headers": {**_DEFAULT_HEADERS},
        "body": json.dumps(body),
    }
