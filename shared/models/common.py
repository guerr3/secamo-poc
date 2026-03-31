"""
shared.models.common — Shared enums used across model layers.
"""

from enum import Enum


class LifecycleAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    PASSWORD_RESET = "password_reset"


# Canonical signal name used by HiTLApprovalWorkflow and all callers that
# dispatch approval signals.  Defined here to guarantee a single source of
# truth for the workflow signal method name and the SignalGateway mapping.
HITL_APPROVAL_SIGNAL_NAME = "approve"
