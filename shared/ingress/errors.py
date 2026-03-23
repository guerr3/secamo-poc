"""Typed ingress error contracts for pipeline stage boundaries.

Responsibility: provide uniform error types for contract-level stage failures.
This module must not contain provider-specific mappings, HTTP framework code, or SDK calls.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IngressErrorCode(str, Enum):
    """High-level stage failure categories for ingress orchestration."""

    VALIDATION = "validation_error"
    AUTHENTICATION = "authentication_error"
    NORMALIZATION = "normalization_error"
    ROUTING = "routing_error"
    DISPATCH = "dispatch_error"
    INTERNAL = "internal_error"


class IngressError(BaseModel):
    """Immutable error payload shared across ingress pipeline contracts."""

    model_config = ConfigDict()

    code: IngressErrorCode
    message: str
    retryable: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class IngressPipelineError(Exception):
    """Exception wrapper carrying a typed ingress error payload."""

    def __init__(self, error: IngressError) -> None:
        super().__init__(error.message)
        self.error = error
