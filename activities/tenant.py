from temporalio import activity
from shared.models import TenantSecrets
from shared.config import (
    GRAPH_TENANT1_ID,
    GRAPH_CLIENT1_ID,
    GRAPH_SECRET1_VALUE,
)

# Tenant registry — maps internal tenant_id to metadata & Azure tenant ID.
# Later: lookup in DynamoDB or AWS SSM Parameter Store.
KNOWN_TENANTS = {
    "tenant-demo-001": {
        "name": "Demo Klant BV",
        "azure_tenant_id": GRAPH_TENANT1_ID,
    },
}


@activity.defn
async def validate_tenant_context(tenant_id: str) -> dict:
    """
    Verifieert dat de tenant bestaat en geeft metadata terug.
    Later: lookup in DynamoDB of SSM Parameter Store.
    """
    activity.logger.info(f"Valideren tenant context voor '{tenant_id}'")

    tenant = KNOWN_TENANTS.get(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant '{tenant_id}' niet gevonden.")

    activity.logger.info(f"Tenant gevalideerd: {tenant['name']}")
    return tenant


@activity.defn
async def get_tenant_secrets(tenant_id: str, secret_type: str) -> TenantSecrets:
    """
    Haalt credentials op voor de tenant.
    Later: AWS SSM Parameter Store / Secrets Manager call.
    Secret path: /secamo/tenants/{tenant_id}/graph
    """
    activity.logger.info(
        f"Ophalen secrets voor tenant '{tenant_id}' (type: {secret_type})"
    )

    # TODO: replace with real SSM/boto3 call
    # Voorlopig gebruiken we de env-variabelen uit shared/config.py
    return TenantSecrets(
        client_id=GRAPH_CLIENT1_ID,
        client_secret=GRAPH_SECRET1_VALUE,
        tenant_azure_id=GRAPH_TENANT1_ID,
    )
