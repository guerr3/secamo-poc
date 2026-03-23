"""Temporal boundary contracts for typed signal dispatching.

Responsibility: expose transport-agnostic dispatch interfaces for workflow signaling.
This package must not contain direct ingress parsing logic or provider-specific validation code.
"""

from .signal_gateway import SignalGateway, SignalTransport
from .dispatcher import RouteFanoutDispatcher, WorkflowStarter

__all__ = ["RouteFanoutDispatcher", "SignalGateway", "SignalTransport", "WorkflowStarter"]
