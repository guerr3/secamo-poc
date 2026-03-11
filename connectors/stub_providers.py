from __future__ import annotations

from connectors.base import BaseConnector


class _StubConnector(BaseConnector):
    provider_name = "stub"

    @property
    def provider(self) -> str:
        return self.provider_name

    async def fetch_events(self, query: dict) -> list:
        # TODO: replace with real provider API integration.
        return []

    async def execute_action(self, action: str, payload: dict) -> dict:
        # TODO: replace with real provider API integration.
        return {"success": False, "reason": f"{self.provider} is not implemented", "action": action}

    async def health_check(self) -> dict:
        # TODO: replace with real provider API integration.
        return {"healthy": False, "provider": self.provider, "details": "stub connector"}


class CrowdStrikeConnector(_StubConnector):
    provider_name = "crowdstrike"


class SentinelOneConnector(_StubConnector):
    provider_name = "sentinelone"


class HaloItsmConnector(_StubConnector):
    provider_name = "halo_itsm"


class ServiceNowConnector(_StubConnector):
    provider_name = "servicenow"


class VirusTotalConnector(_StubConnector):
    provider_name = "virustotal"


class AbuseIpdbConnector(_StubConnector):
    provider_name = "abuseipdb"


class MispConnector(_StubConnector):
    provider_name = "misp"
