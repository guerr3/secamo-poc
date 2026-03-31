"""Capability-first provider interfaces for cross-domain operations.

These protocols define business capabilities independent of provider systems.
Concrete implementations may delegate to connector adapters.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from shared.models.domain import IdentityUser, TicketData, TicketResult


@runtime_checkable
class IdentityAccessProvider(Protocol):
    """Provider contract for identity lifecycle operations."""

    async def get_user(self, email: str) -> IdentityUser | None:
        """Get one identity by e-mail address."""

    async def create_user(self, user_data: dict[str, Any]) -> IdentityUser:
        """Create a new identity from provider-agnostic user data."""

    async def update_user(self, user_id: str, updates: dict[str, Any]) -> bool:
        """Update an existing identity."""

    async def delete_user(self, user_id: str) -> bool:
        """Disable or delete an identity according to provider semantics."""

    async def revoke_sessions(self, user_id: str) -> bool:
        """Revoke active sessions for an identity."""

    async def assign_license(self, user_id: str, sku_id: str) -> bool:
        """Assign a license/entitlement to an identity."""

    async def reset_password(self, user_id: str, temp_password: str) -> bool:
        """Reset password for an identity."""


@runtime_checkable
class TicketingProvider(Protocol):
    """Provider contract for ticketing lifecycle operations."""

    async def create_ticket(self, ticket_data: TicketData) -> TicketResult:
        """Create one ticket from canonical ticket data."""

    async def update_ticket(self, ticket_id: str, update_fields: dict[str, Any]) -> TicketResult:
        """Update one ticket with provider-specific field map."""

    async def close_ticket(self, ticket_id: str, resolution: str) -> TicketResult:
        """Close one ticket with a resolution note/value."""

    async def get_ticket_details(self, ticket_id: str) -> dict[str, Any]:
        """Get provider-normalized ticket details for one ticket id."""
