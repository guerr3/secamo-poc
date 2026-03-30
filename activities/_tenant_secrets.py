from __future__ import annotations

from shared.models import TenantSecrets
from shared.ssm_client import get_secret_bundle


def load_tenant_secrets(tenant_id: str, secret_type: str) -> TenantSecrets:
    bundle = get_secret_bundle(tenant_id, secret_type)
    return TenantSecrets(
        client_id=str(bundle.get("client_id") or ""),
        client_secret=str(bundle.get("client_secret") or ""),
        tenant_azure_id=str(bundle.get("tenant_azure_id") or ""),
        teams_webhook_url=bundle.get("teams_webhook_url") or bundle.get("webhook_url"),
        jira_base_url=bundle.get("jira_base_url") or bundle.get("base_url"),
        jira_email=bundle.get("jira_email"),
        jira_api_token=bundle.get("jira_api_token") or bundle.get("api_token"),
        project_key=bundle.get("project_key"),
        project_type=(bundle.get("project_type") or "standard").strip().lower(),
        jsm_service_desk_id=bundle.get("jsm_service_desk_id"),
        virustotal_api_key=bundle.get("virustotal_api_key") or bundle.get("api_key"),
        abuseipdb_api_key=bundle.get("abuseipdb_api_key") or bundle.get("api_key"),
    )
