"""
shared.models.common — Shared enums used across model layers.
"""

from enum import Enum


class LifecycleAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    PASSWORD_RESET = "password_reset"
