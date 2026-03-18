from __future__ import annotations

from collections.abc import Callable

from connectors.base import BaseConnector
from connectors.jira import JiraConnector
from connectors.microsoft_defender import MicrosoftGraphConnector
from connectors.stub_providers import (
    AbuseIpdbConnector,
    CrowdStrikeConnector,
    HaloItsmConnector,
    MispConnector,
    SentinelOneConnector,
    ServiceNowConnector,
    VirusTotalConnector,
)
from shared.models import TenantSecrets

ConnectorFactory = Callable[[str, TenantSecrets], BaseConnector]


def _factory(cls: type[BaseConnector]) -> ConnectorFactory:
    def build(tenant_id: str, secrets: TenantSecrets) -> BaseConnector:
        return cls(tenant_id=tenant_id, secrets=secrets)

    return build


_CONNECTOR_FACTORIES: dict[str, ConnectorFactory] = {
    "microsoft_defender": _factory(MicrosoftGraphConnector),
    "jira": _factory(JiraConnector),
    "crowdstrike": _factory(CrowdStrikeConnector),
    "sentinelone": _factory(SentinelOneConnector),
    "halo_itsm": _factory(HaloItsmConnector),
    "servicenow": _factory(ServiceNowConnector),
    "virustotal": _factory(VirusTotalConnector),
    "abuseipdb": _factory(AbuseIpdbConnector),
    "misp": _factory(MispConnector),
}


def get_connector(provider: str, tenant_id: str, secrets: TenantSecrets) -> BaseConnector:
    factory = _CONNECTOR_FACTORIES.get(provider.lower())
    if factory is None:
        raise ValueError(f"No connector registered for provider '{provider}'")
    return factory(tenant_id, secrets)


def list_supported_connectors() -> list[str]:
    return sorted(_CONNECTOR_FACTORIES.keys())
