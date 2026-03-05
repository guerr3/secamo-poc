"""
ingress_sdk — Shared Lambda Layer for the Secamo Ingress component.

Provides a standardized toolkit for building ingress Lambda handlers
that route events to the Temporal workflow engine.

Modules:
    temporal  — Singleton gRPC client + start_workflow / signal_workflow
    event     — IngressEvent parser for API Gateway proxy events
    response  — ok() / accepted() / error() response helpers
    dispatch  — async_handler() factory for route-based Lambda handlers
"""

from ingress_sdk.event import IngressEvent, parse
from ingress_sdk.response import ok, accepted, error
from ingress_sdk.dispatch import async_handler

__all__ = [
    "IngressEvent",
    "parse",
    "ok",
    "accepted",
    "error",
    "async_handler",
]
