"""Provider type system and secret mapping.

This module is the single source of truth for provider identifiers and
provider-to-secret-bundle mappings used by adapters and activities.
"""

from __future__ import annotations

from typing import Literal, TypeAlias

ProviderSecretType: TypeAlias = Literal["graph", "ticketing", "threatintel", "chatops"]
AIProviderType: TypeAlias = Literal["azure_openai", "aws_bedrock", "local"]
ChatOpsProviderType: TypeAlias = Literal["ms_teams", "slack"]
IAMProviderType: TypeAlias = Literal["microsoft_graph", "okta", "entra_id", "custom"]
EDRProviderType: TypeAlias = Literal["microsoft_defender", "crowdstrike", "sentinelone"]
TicketingProviderType: TypeAlias = Literal["jira", "halo_itsm", "servicenow"]
ThreatIntelProviderType: TypeAlias = Literal["virustotal", "abuseipdb", "misp"]
NotificationProviderType: TypeAlias = Literal["teams", "slack", "email"]

_SECRET_TYPE_BY_PROVIDER: dict[str, ProviderSecretType] = {
    "microsoft_defender": "graph",
    "crowdstrike": "graph",
    "sentinelone": "graph",
    "defender": "graph",
    "microsoft_graph": "graph",
    "entra_id": "graph",
    "jira": "ticketing",
    "halo_itsm": "ticketing",
    "servicenow": "ticketing",
    "virustotal": "threatintel",
    "abuseipdb": "threatintel",
    "misp": "threatintel",
    "teams": "chatops",
    "slack": "chatops",
    "email": "chatops",
}


def secret_type_for_provider(provider: str) -> ProviderSecretType:
    """Resolve SSM secret bundle type for a provider name."""
    normalized = provider.strip().lower()
    secret_type = _SECRET_TYPE_BY_PROVIDER.get(normalized)
    if secret_type is None:
        raise ValueError(f"No secret type mapping defined for provider '{provider}'")
    return secret_type
