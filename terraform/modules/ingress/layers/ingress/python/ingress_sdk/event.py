"""
ingress_sdk.event — Standardized API Gateway event parsing.

Extracts tenant context from the Lambda Authorizer and normalizes
the raw API Gateway proxy event into a clean IngressEvent dataclass.
"""

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("ingress_sdk.event")


@dataclass
class IngressEvent:
    """Parsed and normalized API Gateway proxy event."""

    tenant_id: str
    path: str
    method: str
    body: dict
    source_ip: str
    request_id: str
    headers: dict = field(default_factory=dict)


def parse(event: dict) -> IngressEvent:
    """
    Parse a raw API Gateway REST proxy event into an IngressEvent.

    Extracts:
      - tenant_id from requestContext.authorizer (injected by Lambda Authorizer)
      - body from the JSON-encoded body string
      - source_ip, request_id, headers for tracing

    Args:
        event: Raw Lambda event dict from API Gateway proxy integration.

    Returns:
        IngressEvent with all fields populated.

    Raises:
        ValueError: If the request body contains invalid JSON.
    """
    request_context = event.get("requestContext", {})
    authorizer = request_context.get("authorizer", {})
    identity = request_context.get("identity", {})

    # Parse JSON body
    raw_body = event.get("body")
    if raw_body:
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Invalid JSON in request body: {exc}") from exc
    else:
        body = {}

    return IngressEvent(
        tenant_id=authorizer.get("tenant_id", "unknown"),
        path=event.get("path", ""),
        method=event.get("httpMethod", ""),
        body=body,
        source_ip=identity.get("sourceIp", "unknown"),
        request_id=request_context.get("requestId", ""),
        headers=event.get("headers", {}),
    )
