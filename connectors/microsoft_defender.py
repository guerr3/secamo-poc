from __future__ import annotations

from typing import Any

from connectors.base import BaseConnector
from connectors.errors import ConnectorUnsupportedActionError
from shared.models import Envelope


class MicrosoftGraphConnector(BaseConnector):
    """Deprecated connector shim.

    Active Microsoft Graph/Defender logic moved to capability-scoped connectors in
    connectors.microsoft.capability.
    """

    @property
    def provider(self) -> str:
        return "microsoft_defender"

    async def fetch_events(self, query: dict[str, Any]) -> list[Envelope]:
        raise ConnectorUnsupportedActionError(
            "MicrosoftGraphConnector is deprecated. Use scoped connectors: "
            "microsoft_defender_edr, microsoft_graph_identity, or microsoft_graph_subscription."
        )

    async def execute_action(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise ConnectorUnsupportedActionError(
            "MicrosoftGraphConnector is deprecated. Use scoped connectors: "
            "microsoft_defender_edr, microsoft_graph_identity, or microsoft_graph_subscription."
        )

    async def health_check(self) -> dict[str, Any]:
        raise ConnectorUnsupportedActionError(
            "MicrosoftGraphConnector is deprecated. Use scoped connectors: "
            "microsoft_defender_edr, microsoft_graph_identity, or microsoft_graph_subscription."
        )


MicrosoftDefenderConnector = MicrosoftGraphConnector
