"""Protocol interfaces for ingress pipeline stages.

Responsibility: declare typed stage contracts used by ingress orchestration.
This module must not contain concrete implementations, provider-specific branching, or SDK integrations.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .contracts import (
    AuthResult,
    DispatchPlan,
    DispatchResult,
    IngressContext,
    IngressRequest,
    IngressSignal,
)


@runtime_checkable
class AuthenticateStage(Protocol):
    """Stage contract for request authentication and principal attribution."""

    async def __call__(self, request: IngressRequest, context: IngressContext) -> AuthResult:
        """Authenticate the ingress request and return immutable auth metadata."""


@runtime_checkable
class NormalizeStage(Protocol):
    """Stage contract for converting request input into normalized intent signals."""

    async def __call__(
        self,
        request: IngressRequest,
        context: IngressContext,
        auth: AuthResult,
    ) -> IngressSignal:
        """Normalize validated request data into a provider-agnostic signal."""


@runtime_checkable
class RouteStage(Protocol):
    """Stage contract for converting normalized signals into dispatch plans."""

    async def __call__(
        self,
        signal: IngressSignal,
        request: IngressRequest,
        context: IngressContext,
    ) -> DispatchPlan:
        """Resolve routes for a normalized signal and produce a dispatch plan."""


@runtime_checkable
class DispatchStage(Protocol):
    """Stage contract for dispatching route plans to workflow infrastructure."""

    async def __call__(self, plan: DispatchPlan, context: IngressContext) -> DispatchResult:
        """Dispatch a prepared route plan and return aggregated dispatch status."""
