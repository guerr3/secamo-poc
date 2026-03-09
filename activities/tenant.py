import boto3
from temporalio import activity
from temporalio.exceptions import ApplicationError
from shared.models import TenantSecrets

# We initialize the SSM client at the module level so it can be reused across activity invocations
# but since AWS credentials need to be picked up by boto3 automatically, this is fine.
ssm_client = boto3.client("ssm")

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

    # Zorg ervoor dat we alle benodigde parameters hebben
    client_id = parameters.get("client_id")
    client_secret = parameters.get("client_secret")
    tenant_azure_id = parameters.get("tenant_azure_id")

    if not all([client_id, client_secret, tenant_azure_id]):
        activity.logger.error(f"Ontbrekende parameters voor tenant {tenant_id}. Gevonden: {list(parameters.keys())}")
        raise ApplicationError(
            f"Configuratie voor tenant '{tenant_id}' ({secret_type}) is incompleet of bestaat niet.",
            type="MissingTenantConfigError",
            non_retryable=True
        )

    return TenantSecrets(
        client_id=client_id,
        client_secret=client_secret,
        tenant_azure_id=tenant_azure_id,
    )
