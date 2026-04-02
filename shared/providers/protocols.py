"""Provider and connector protocols.

Provider contracts live in shared.providers as the integration-edge source of
truth, while domain payload models remain in shared.models.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from shared.models.canonical import Envelope
from shared.models.chatops import ChatOpsMessage
from shared.models.domain import (
    DeviceContext,
    IdentityRiskContext,
    IdentityUser,
    ThreatIntelResult,
    TicketData,
    TicketResult,
)
from shared.models.subscriptions import SubscriptionConfig, SubscriptionState
from shared.models.triage import TriageRequest, TriageResult


@runtime_checkable
class ConnectorInterface(Protocol):
    """Protocol contract implemented by connector adapters."""

    @property
    def provider(self) -> str:
        """Stable provider identifier used by the registry."""

    async def fetch_events(self, query: dict[str, Any]) -> list[Envelope]:
        """Fetch and normalize provider events into Envelope objects."""

    async def execute_action(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a provider action (remediation, ticketing, enrichment, etc.)."""

    async def health_check(self) -> dict[str, Any]:
        """Verify connector health and return provider-specific diagnostics."""


@runtime_checkable
class IdentityAccessProvider(Protocol):
    """Provider contract for identity lifecycle operations."""

    async def get_user(self, email: str) -> IdentityUser | None: ...
    async def create_user(self, user_data: dict[str, Any]) -> IdentityUser: ...
    async def update_user(self, user_id: str, updates: dict[str, Any]) -> bool: ...
    async def delete_user(self, user_id: str) -> bool: ...
    async def revoke_sessions(self, user_id: str) -> bool: ...
    async def assign_license(self, user_id: str, sku_id: str) -> bool: ...
    async def reset_password(self, user_id: str, temp_password: str) -> bool: ...


@runtime_checkable
class TicketingProvider(Protocol):
    """Provider contract for ticketing lifecycle operations."""

    async def create_ticket(self, ticket_data: TicketData) -> TicketResult: ...
    async def update_ticket(self, ticket_id: str, update_fields: dict[str, Any]) -> TicketResult: ...
    async def close_ticket(self, ticket_id: str, resolution: str) -> TicketResult: ...
    async def get_ticket_details(self, ticket_id: str) -> dict[str, Any]: ...


@runtime_checkable
class AITriageProvider(Protocol):
    """Provider contract for asynchronous AI triage implementations."""

    async def analyze_alert(self, request: TriageRequest) -> TriageResult: ...


@runtime_checkable
class ChatOpsProvider(Protocol):
    """Provider contract for ChatOps transport and webhook verification."""

    async def send_message(self, target_channel: str, message: ChatOpsMessage) -> str: ...
    async def validate_webhook_signature(self, headers: dict[str, str], body: bytes) -> bool: ...


@runtime_checkable
class EDRProvider(Protocol):
    """Provider contract for EDR operations."""

    async def fetch_events(self, query: dict[str, Any]) -> list[Envelope]: ...
    async def enrich_alert(self, alert_id: str, context: dict[str, Any] | None = None) -> dict[str, Any]: ...
    async def get_device_context(self, device_id: str) -> DeviceContext | None: ...
    async def isolate_device(self, device_id: str, comment: str) -> bool: ...
    async def unisolate_device(self, device_id: str, comment: str) -> bool: ...
    async def run_antivirus_scan(self, device_id: str, scan_type: str) -> dict[str, Any]: ...
    async def list_noncompliant_devices(self) -> list[dict[str, Any]]: ...
    async def get_user_alerts(self, user_email: str, top: int = 10) -> list[dict[str, Any]]: ...
    async def confirm_user_compromised(self, user_id: str) -> bool: ...
    async def dismiss_risky_user(self, user_id: str) -> bool: ...
    async def get_signin_history(self, user_principal_name: str, top: int = 20) -> list[dict[str, Any]]: ...
    async def list_risky_users(self, min_risk_level: str) -> list[dict[str, Any]]: ...
    async def get_identity_risk(self, lookup_key: str) -> IdentityRiskContext | None: ...


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Provider contract for threat-intelligence enrichment operations."""

    async def lookup_indicator(
        self,
        indicator: str,
        *,
        provider_override: str | None = None,
    ) -> ThreatIntelResult: ...

    async def fanout(
        self,
        indicator: str,
        providers: list[str],
    ) -> ThreatIntelResult: ...


@runtime_checkable
class SubscriptionProvider(Protocol):
    """Provider contract for Graph-style webhook subscription lifecycle + metadata."""

    async def create_subscription(
        self,
        subscription: SubscriptionConfig,
        *,
        secret_type: str,
        notification_url: str,
        client_state: str,
    ) -> SubscriptionState: ...

    async def renew_subscription(
        self,
        subscription_id: str,
        *,
        expiration_hours: int,
        secret_type: str,
    ) -> SubscriptionState: ...

    async def delete_subscription(
        self,
        subscription_id: str,
        *,
        secret_type: str,
    ) -> bool: ...

    async def list_subscriptions(
        self,
        *,
        secret_type: str,
    ) -> list[SubscriptionState]: ...

    async def store_metadata(self, state: SubscriptionState) -> dict[str, Any]: ...
    async def load_metadata(self, tenant_id: str) -> list[SubscriptionState]: ...
    async def lookup_metadata(self, subscription_id: str) -> SubscriptionState | None: ...
