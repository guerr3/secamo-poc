"""Routing contracts for ingress-owned workflow dispatch planning.

Responsibility: provide route definitions and registry utilities for intent fan-out dispatch.
This package must not contain provider-specific normalizer parsing or workflow activity implementations.
"""

from .contracts import DispatchReport, RouteFailure, WorkflowRoute
from .defaults import (
    build_default_route_registry,
    resolve_polling_route,
    resolve_provider_event_route,
    resolve_webhook_route,
)
from .registry import RouteRegistry

__all__ = [
    "DispatchReport",
    "RouteFailure",
    "RouteRegistry",
    "WorkflowRoute",
    "build_default_route_registry",
    "resolve_polling_route",
    "resolve_provider_event_route",
    "resolve_webhook_route",
]
