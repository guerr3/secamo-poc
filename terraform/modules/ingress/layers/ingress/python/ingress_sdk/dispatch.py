"""
ingress_sdk.dispatch — Async route dispatch for Lambda handlers.

Provides the `async_handler` factory that converts a route map
into a standard Lambda handler with event parsing, routing,
async execution, and structured error handling.
"""

import asyncio
import logging
from typing import Any, Awaitable, Callable

from ingress_sdk.event import IngressEvent, parse
from ingress_sdk import response

logger = logging.getLogger("ingress_sdk.dispatch")

# Type alias for route handler functions
RouteHandler = Callable[[IngressEvent], Awaitable[dict]]


def async_handler(route_map: dict[str, RouteHandler]) -> Callable:
    """
    Factory that creates a Lambda handler from a route map.

    Usage:
        async def handle_defender(event: IngressEvent) -> dict:
            ...
            return response.accepted({"workflow_id": "..."})

        handler = async_handler({
            "/api/v1/ingress/defender": handle_defender,
        })

    The returned handler will:
      1. Parse the raw API Gateway event into an IngressEvent
      2. Match the path to a route handler
      3. Execute the async handler via asyncio
      4. Return a structured JSON response (including errors)

    Args:
        route_map: Dict mapping path strings to async handler functions.

    Returns:
        A synchronous Lambda handler function.
    """

    def _handler(event: dict[str, Any], context: Any) -> dict:
        # 1. Parse event
        try:
            ingress_event = parse(event)
        except ValueError as exc:
            logger.warning("Event parsing failed: %s", exc)
            return response.error(400, str(exc))

        logger.info(
            "Request: method=%s path=%s tenant=%s ip=%s",
            ingress_event.method,
            ingress_event.path,
            ingress_event.tenant_id,
            ingress_event.source_ip,
        )

        # 2. Route to handler
        route_fn = route_map.get(ingress_event.path)
        if route_fn is None:
            return response.error(404, f"Unknown route: {ingress_event.path}")

        # 3. Execute async handler
        try:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(route_fn(ingress_event))
        except Exception as exc:
            logger.exception("Unhandled error on %s", ingress_event.path)
            return response.error(500, f"Internal server error: {exc}")

    return _handler
