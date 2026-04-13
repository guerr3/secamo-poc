"""Provider-edge contracts used by adapters and connectors.

These types are intentionally placed outside shared.models.domain to prevent
provider-specific secret structures from leaking into workflow domain contracts.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class TenantSecrets(BaseModel):
    """Normalized tenant secrets used by provider adapters/connectors."""

    model_config = ConfigDict(from_attributes=True, frozen=True)

    client_id: str
    client_secret: str = Field(repr=False)
    tenant_azure_id: str
    teams_webhook_url: Optional[str] = Field(default=None, repr=False)
    jira_base_url: Optional[str] = None
    jira_email: Optional[str] = None
    jira_api_token: Optional[str] = Field(default=None, repr=False)
    project_key: Optional[str] = None
    project_type: Literal["jsm", "standard"] = "standard"
    jsm_service_desk_id: Optional[str] = None
    jsm_request_type_id: Optional[str] = None
    virustotal_api_key: Optional[str] = Field(default=None, repr=False)
    abuseipdb_api_key: Optional[str] = Field(default=None, repr=False)