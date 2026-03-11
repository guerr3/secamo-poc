import boto3
from temporalio import activity
from temporalio.exceptions import ApplicationError
from shared.models import TenantConfig, TenantSecrets

# We initialize the SSM client at the module level so it can be reused across activity invocations
# but since AWS credentials need to be picked up by boto3 automatically, this is fine.
ssm_client = boto3.client("ssm", region_name="eu-west-1")

# Tenant registry — maps internal tenant_id to metadata & Azure tenant ID.
# TODO: lookup metadata in DynamoDB. For now, we still hardcode the mapping or we rely entirely on SSM.
KNOWN_TENANTS = {
    "tenant-demo-001": {
        "name": "Demo Klant BV",
    },
}


@activity.defn
async def validate_tenant_context(tenant_id: str) -> dict:
    """
    Verifieert dat de tenant bestaat en geeft metadata terug.
    Later: lookup in DynamoDB (voor metadata). SECRETS worden via SSM beheerd.
    """
    activity.logger.info(f"Valideren tenant context voor '{tenant_id}'")

    tenant = KNOWN_TENANTS.get(tenant_id)
    if not tenant:
        raise ApplicationError(f"Tenant '{tenant_id}' niet gevonden.", non_retryable=True)

    activity.logger.info(f"Tenant gevalideerd: {tenant['name']}")
    return tenant


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@activity.defn
async def get_tenant_config(tenant_id: str) -> TenantConfig:
    """
    Haalt operationele tenantconfig op uit SSM en past defaults toe voor ontbrekende velden.
    Pad: /secamo/tenants/{tenant_id}/config/
    """
    activity.logger.info(f"Ophalen tenant config voor '{tenant_id}' via SSM")
    path = f"/secamo/tenants/{tenant_id}/config/"

    try:
        response = ssm_client.get_parameters_by_path(Path=path, WithDecryption=False)
        parameters = {p["Name"].split("/")[-1]: p["Value"] for p in response.get("Parameters", [])}
    except Exception as e:
        activity.logger.warning(
            f"SSM config ophalen mislukt voor tenant '{tenant_id}', defaults worden gebruikt: {e}"
        )
        parameters = {}

    config = TenantConfig(
        tenant_id=tenant_id,
        display_name=parameters.get("display_name") or KNOWN_TENANTS.get(tenant_id, {}).get("name", "Unknown Tenant"),
        edr_provider=parameters.get("edr_provider", "microsoft_defender"),
        ticketing_provider=parameters.get("ticketing_provider", "jira"),
        threat_intel_providers=[
            p.strip() for p in parameters.get("threat_intel_providers", "virustotal").split(",") if p.strip()
        ]
        or ["virustotal"],
        notification_provider=parameters.get("notification_provider", "teams"),
        sla_tier=parameters.get("sla_tier", "standard"),
        hitl_timeout_hours=_parse_int(parameters.get("hitl_timeout_hours"), 4),
        escalation_enabled=_parse_bool(parameters.get("escalation_enabled"), True),
        auto_isolate_on_timeout=_parse_bool(parameters.get("auto_isolate_on_timeout"), False),
        max_activity_attempts=_parse_int(parameters.get("max_activity_attempts"), 3),
        threat_intel_enabled=_parse_bool(parameters.get("threat_intel_enabled"), True),
        evidence_bundle_enabled=_parse_bool(parameters.get("evidence_bundle_enabled"), True),
        auto_ticket_creation=_parse_bool(parameters.get("auto_ticket_creation"), True),
        misp_sharing_enabled=_parse_bool(parameters.get("misp_sharing_enabled"), False),
    )

    activity.logger.info(f"Tenant config geladen voor '{tenant_id}': {config.model_dump()}")
    return config


@activity.defn
async def get_tenant_secrets(tenant_id: str, secret_type: str) -> TenantSecrets:
    """
    Haalt credentials op voor de tenant via AWS SSM Parameter Store.
    Verwacht parameters onder het pad: /secamo/tenants/{tenant_id}/{secret_type}/
    Bijvoorbeeld:
      - /secamo/tenants/tenant-demo-001/graph/client_id
      - /secamo/tenants/tenant-demo-001/graph/client_secret
      - /secamo/tenants/tenant-demo-001/graph/tenant_azure_id
    """
    activity.logger.info(
        f"Ophalen secrets voor tenant '{tenant_id}' (type: {secret_type}) via SSM"
    )

    path = f"/secamo/tenants/{tenant_id}/{secret_type}/"
    
    try:
        response = ssm_client.get_parameters_by_path(
            Path=path,
            WithDecryption=True
        )
    except Exception as e:
        activity.logger.error(f"Fout bij ophalen SSM parameters voor {tenant_id}: {e}")
        raise ApplicationError(
            f"Fout bij ophalen tenant configuratie: {str(e)}", 
            type="SSMError", 
            non_retryable=False
        )

    parameters = {p["Name"].split("/")[-1]: p["Value"] for p in response.get("Parameters", [])}

    def _build_optional() -> dict:
        return {
            "teams_webhook_url": parameters.get("teams_webhook_url") or parameters.get("webhook_url"),
            "jira_base_url": parameters.get("jira_base_url") or parameters.get("base_url"),
            "jira_email": parameters.get("jira_email"),
            "jira_api_token": parameters.get("jira_api_token") or parameters.get("api_token"),
            "project_key": parameters.get("project_key"),
            "virustotal_api_key": parameters.get("virustotal_api_key") or parameters.get("api_key"),
            "abuseipdb_api_key": parameters.get("abuseipdb_api_key") or parameters.get("api_key"),
        }

    if secret_type == "graph":
        client_id = parameters.get("client_id")
        client_secret = parameters.get("client_secret")
        tenant_azure_id = parameters.get("tenant_azure_id")

        if not all([client_id, client_secret, tenant_azure_id]):
            activity.logger.error(
                f"Ontbrekende graph-parameters voor tenant {tenant_id}. Gevonden keys: {list(parameters.keys())}"
            )
            raise ApplicationError(
                f"Configuratie voor tenant '{tenant_id}' ({secret_type}) is incompleet of bestaat niet.",
                type="MissingTenantConfigError",
                non_retryable=True,
            )

        return TenantSecrets(
            client_id=client_id,
            client_secret=client_secret,
            tenant_azure_id=tenant_azure_id,
            **_build_optional(),
        )

    # Connector-oriented secret types can be partially populated.
    return TenantSecrets(
        client_id=parameters.get("client_id", ""),
        client_secret=parameters.get("client_secret", ""),
        tenant_azure_id=parameters.get("tenant_azure_id", ""),
        **_build_optional(),
    )
