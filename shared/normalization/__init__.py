"""Normalization package for intent-oriented ingress contracts.

Responsibility: expose public WorkflowIntent contracts and keep canonical event internals private.
This package must not expose provider-specific route tables or workflow/activity implementations.
"""

from .contracts import WorkflowIntent

__all__ = ["WorkflowIntent"]
