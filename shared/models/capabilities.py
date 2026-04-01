"""Compatibility re-exports for provider protocols.

Canonical provider contracts are defined in ``shared.providers.protocols``.
This module is retained for backward-compatible imports.
"""

from __future__ import annotations

from shared.providers.protocols import IdentityAccessProvider, TicketingProvider

__all__ = ["IdentityAccessProvider", "TicketingProvider"]
