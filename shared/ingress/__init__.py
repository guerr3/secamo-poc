"""Ingress contract package for phase-1 architecture boundaries.

Responsibility: expose provider-agnostic pipeline contracts used by ingress orchestration.
This package must not contain provider-specific logic, AWS SDK usage, or Temporal SDK calls.
"""

from .contracts import (
    AuthResult,
    DispatchItem,
    DispatchPlan,
    DispatchResult,
    IngressContext,
    IngressOutcome,
    IngressRequest,
    IngressSignal,
)
from .errors import IngressError, IngressErrorCode, IngressPipelineError

__all__ = [
    "AuthResult",
    "DispatchItem",
    "DispatchPlan",
    "DispatchResult",
    "IngressContext",
    "IngressError",
    "IngressErrorCode",
    "IngressOutcome",
    "IngressPipelineError",
    "IngressRequest",
    "IngressSignal",
]
