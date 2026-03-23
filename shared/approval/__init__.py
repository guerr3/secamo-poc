"""Approval signal contracts for callback normalization and dispatch boundaries.

Responsibility: expose typed discriminated signal payload models used across callback channels.
This package must not contain provider webhook parsing implementations or Temporal SDK calls.
"""

from .callbacks import normalize_approval_callback
from .contracts import ApprovalSignal, GenericActionSignal, SignalPayload
from .token_store import DEFAULT_HITL_TOKEN_TTL_SECONDS, HITL_TOKEN_TTL_ENV_VAR, DynamoDbHitlTokenStore, get_hitl_token_ttl_seconds

__all__ = [
	"ApprovalSignal",
	"DEFAULT_HITL_TOKEN_TTL_SECONDS",
	"DynamoDbHitlTokenStore",
	"GenericActionSignal",
	"HITL_TOKEN_TTL_ENV_VAR",
	"SignalPayload",
	"get_hitl_token_ttl_seconds",
	"normalize_approval_callback",
]
