from __future__ import annotations

from abc import ABC, abstractmethod

from shared.models import Envelope
from shared.providers.contracts import TenantSecrets


class BaseConnector(ABC):
    """Provider-agnostic contract for external integrations."""

    def __init__(self, tenant_id: str, secrets: TenantSecrets) -> None:
        self.tenant_id = tenant_id
        self.secrets = secrets

    @property
    @abstractmethod
    def provider(self) -> str:
        """Stable provider identifier used by the registry."""

    @abstractmethod
    async def fetch_events(self, query: dict) -> list[Envelope]:
        """Fetch and normalize provider events into Envelope objects."""

    @abstractmethod
    async def execute_action(self, action: str, payload: dict) -> dict:
        """Execute a provider action (remediation, ticketing, enrichment, etc.)."""

    @abstractmethod
    async def health_check(self) -> dict:
        """Verify connector health and return provider-specific diagnostics."""
