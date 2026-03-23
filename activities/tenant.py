import asyncio
import json
import os
from typing import Any

import boto3
from temporalio import activity
from temporalio.exceptions import ApplicationError
from shared.models import (
    GraphSubscriptionConfig,
    PollingProviderConfig,
    TenantConfig,
    TenantSecrets,
)


ssm_client = None
dynamodb = None
TENANT_TABLE_NAME = os.environ.get("TENANT_TABLE_NAME", "").strip()


def _get_ssm_client():
    global ssm_client
    if ssm_client is None:
        ssm_client = boto3.client("ssm", region_name="eu-west-1")
    return ssm_client


def _get_dynamodb_resource():
    global dynamodb
    if dynamodb is None:
        dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    return dynamodb


def _ssm_get_parameters_by_path(path: str, with_decryption: bool) -> list[dict[str, Any]]:
    """Fetch all SSM parameters for a path with pagination support."""
    client = _get_ssm_client()
    next_token: str | None = None
    collected: list[dict[str, Any]] = []

    while True:
        request: dict[str, Any] = {
            "Path": path,
            "WithDecryption": with_decryption,
            "Recursive": True,
        }
        if next_token:
            request["NextToken"] = next_token

        response = client.get_parameters_by_path(**request)
        collected.extend(response.get("Parameters", []))
        next_token = response.get("NextToken")
        if not next_token:
            break

    return collected


def _discover_tenants_from_ssm() -> list[dict[str, Any]]:
    """Discover tenant IDs and optional display names from /secamo/tenants paths."""
    try:
        parameters = _ssm_get_parameters_by_path("/secamo/tenants/", with_decryption=False)
    except Exception as exc:
        activity.logger.warning("Tenant discovery via SSM failed: %s", exc)
        return []

    tenant_map: dict[str, dict[str, Any]] = {}
    for parameter in parameters:
        name = str(parameter.get("Name") or "")
        parts = [part for part in name.split("/") if part]
        if len(parts) < 3 or parts[0] != "secamo" or parts[1] != "tenants":
            continue

        tenant_id = parts[2].strip()
        if not tenant_id:
            continue

        entry = tenant_map.setdefault(
            tenant_id,
            {"tenant_id": tenant_id, "name": tenant_id, "active": True},
        )

        if len(parts) >= 5 and parts[3] == "config" and parts[4] == "display_name":
            value = str(parameter.get("Value") or "").strip()
            if value:
                entry["name"] = value

    return list(tenant_map.values())


@activity.defn
async def get_all_active_tenants() -> list[dict]:
    """Load active tenants from DynamoDB, falling back to SSM tenant discovery."""
    if TENANT_TABLE_NAME:
        try:
            table = _get_dynamodb_resource().Table(TENANT_TABLE_NAME)
            items: list[dict[str, Any]] = []
            last_key: dict[str, Any] | None = None
            while True:
                scan_kwargs: dict[str, Any] = {
                    "ProjectionExpression": "tenant_id, display_name, #status",
                    "ExpressionAttributeNames": {"#status": "status"},
                }
                if last_key is not None:
                    scan_kwargs["ExclusiveStartKey"] = last_key

                response = await asyncio.to_thread(lambda: table.scan(**scan_kwargs))
                items.extend(response.get("Items", []))
                activity.heartbeat({"stage": "tenant_scan", "items": len(items)})
                last_key = response.get("LastEvaluatedKey")
                if not last_key:
                    break

            tenants: list[dict[str, Any]] = []
            for item in items:
                status = str(item.get("status", "active")).lower()
                if status not in {"active", "enabled", "true", "1"}:
                    continue

                tenant_id = str(item.get("tenant_id", "")).strip()
                if not tenant_id:
                    continue

                tenants.append(
                    {
                        "tenant_id": tenant_id,
                        "name": str(item.get("display_name") or tenant_id),
                        "active": True,
                    }
                )

            if tenants:
                return tenants
        except Exception as exc:
            activity.logger.warning("Tenant scan via DynamoDB failed: %s", exc)

    return await asyncio.to_thread(_discover_tenants_from_ssm)


@activity.defn
async def validate_tenant_context(tenant_id: str) -> dict:
    """
    Verifieert dat de tenant bestaat en geeft metadata terug.
    Later: lookup in DynamoDB (voor metadata). SECRETS worden via SSM beheerd.
    """
    activity.logger.info(f"Valideren tenant context voor '{tenant_id}'")

    active_tenants = await get_all_active_tenants()
    tenant = next((item for item in active_tenants if item["tenant_id"] == tenant_id), None)
    if tenant is None:
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


def _parse_polling_providers(raw_value: str | None) -> list[PollingProviderConfig]:
    if not raw_value:
        return []

    providers: list[PollingProviderConfig] = []
    for entry in raw_value.split(","):
        chunk = entry.strip()
        if not chunk:
            continue

        parts = [part.strip() for part in chunk.split(":")]
        if len(parts) < 2:
            activity.logger.warning("Ongeldige polling_providers entry overgeslagen: '%s'", chunk)
            continue

        provider = parts[0]
        resource_type = parts[1]
        secret_type = parts[2] if len(parts) > 2 and parts[2] else "graph"
        poll_interval_seconds = _parse_int(parts[3] if len(parts) > 3 else None, 300)

        providers.append(
            PollingProviderConfig(
                provider=provider,
                resource_type=resource_type,
                secret_type=secret_type,
                poll_interval_seconds=poll_interval_seconds,
            )
        )

    return providers


def _parse_graph_subscriptions(raw_value: str | None) -> list[GraphSubscriptionConfig]:
    if not raw_value:
        return []

    parsed_json: list[dict] | None = None
    try:
        value = json.loads(raw_value)
        if isinstance(value, list):
            parsed_json = [item for item in value if isinstance(item, dict)]
    except json.JSONDecodeError:
        parsed_json = None

    if parsed_json is not None:
        configs: list[GraphSubscriptionConfig] = []
        for item in parsed_json:
            try:
                configs.append(GraphSubscriptionConfig.model_validate(item))
            except Exception:
                activity.logger.warning("Ongeldige graph_subscriptions JSON entry overgeslagen: %s", item)
        return configs

    providers: list[GraphSubscriptionConfig] = []
    for entry in raw_value.split(","):
        chunk = entry.strip()
        if not chunk:
            continue

        parts = [part.strip() for part in chunk.split(":")]
        if len(parts) < 1:
            continue

        resource = parts[0]
        change_types = [p for p in (parts[1].split("+") if len(parts) > 1 and parts[1] else ["created", "updated"]) if p]
        include_resource_data = _parse_bool(parts[2] if len(parts) > 2 else None, False)
        expiration_hours = _parse_int(parts[3] if len(parts) > 3 else None, 24)

        providers.append(
            GraphSubscriptionConfig(
                resource=resource,
                change_types=change_types,
                include_resource_data=include_resource_data,
                expiration_hours=expiration_hours,
            )
        )

    return providers


@activity.defn
async def get_tenant_config(tenant_id: str) -> TenantConfig:
    """
    Haalt operationele tenantconfig op uit SSM en past defaults toe voor ontbrekende velden.
    Pad: /secamo/tenants/{tenant_id}/config/
    """
    activity.logger.info(f"Ophalen tenant config voor '{tenant_id}' via SSM")
    path = f"/secamo/tenants/{tenant_id}/config/"

    try:
        ssm_parameters = await asyncio.to_thread(_ssm_get_parameters_by_path, path, False)
        parameters = {p["Name"].split("/")[-1]: p["Value"] for p in ssm_parameters}
    except Exception as e:
        activity.logger.warning(
            f"SSM config ophalen mislukt voor tenant '{tenant_id}', defaults worden gebruikt: {e}"
        )
        parameters = {}

    tenant_registry = {item["tenant_id"]: item for item in await get_all_active_tenants()}

    config = TenantConfig(
        tenant_id=tenant_id,
        display_name=parameters.get("display_name") or tenant_registry.get(tenant_id, {}).get("name", "Unknown Tenant"),
        edr_provider=parameters.get("edr_provider", "microsoft_defender"),
        ticketing_provider=parameters.get("ticketing_provider", "jira"),
        threat_intel_providers=[
            p.strip() for p in parameters.get("threat_intel_providers", "virustotal").split(",") if p.strip()
        ]
        or ["virustotal"],
        notification_provider=parameters.get("notification_provider", "teams"),
        soc_analyst_email=parameters.get("soc_analyst_email"),
        sla_tier=parameters.get("sla_tier", "standard"),
        hitl_timeout_hours=_parse_int(parameters.get("hitl_timeout_hours"), 4),
        escalation_enabled=_parse_bool(parameters.get("escalation_enabled"), True),
        auto_isolate_on_timeout=_parse_bool(parameters.get("auto_isolate_on_timeout"), False),
        max_activity_attempts=_parse_int(parameters.get("max_activity_attempts"), 3),
        threat_intel_enabled=_parse_bool(parameters.get("threat_intel_enabled"), True),
        evidence_bundle_enabled=_parse_bool(parameters.get("evidence_bundle_enabled"), True),
        auto_ticket_creation=_parse_bool(parameters.get("auto_ticket_creation"), True),
        misp_sharing_enabled=_parse_bool(parameters.get("misp_sharing_enabled"), False),
        polling_providers=_parse_polling_providers(parameters.get("polling_providers")),
        graph_subscriptions=_parse_graph_subscriptions(parameters.get("graph_subscriptions")),
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
        ssm_parameters = await asyncio.to_thread(_ssm_get_parameters_by_path, path, True)
    except Exception as e:
        activity.logger.error(f"Fout bij ophalen SSM parameters voor {tenant_id}: {e}")
        raise ApplicationError(
            f"Fout bij ophalen tenant configuratie: {str(e)}", 
            type="SSMError", 
            non_retryable=False
        )

    parameters = {p["Name"].split("/")[-1]: p["Value"] for p in ssm_parameters}

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
            client_id=str(client_id),
            client_secret=str(client_secret),
            tenant_azure_id=str(tenant_azure_id),
            **_build_optional(),
        )

    # Connector-oriented secret types can be partially populated.
    return TenantSecrets(
        client_id=parameters.get("client_id", ""),
        client_secret=parameters.get("client_secret", ""),
        tenant_azure_id=parameters.get("tenant_azure_id", ""),
        **_build_optional(),
    )
