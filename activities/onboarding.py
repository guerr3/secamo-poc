from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from typing import Any
from urllib.parse import urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from temporalio import activity

from activities._activity_errors import raise_activity_error
from shared.models.canonical import CustomerOnboardingEvent
from shared.ssm_client import put_secret


TENANT_TABLE_NAME = os.environ.get("TENANT_TABLE_NAME", "").strip()
_dynamodb = None


def _get_dynamodb_resource():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
    return _dynamodb


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    if value is None:
        return ""
    return str(value)


def _is_partial_onboarding_enabled(payload: CustomerOnboardingEvent) -> bool:
    raw = payload.config.get("allow_partial_onboarding") if isinstance(payload.config, dict) else None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _normalize_base_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid public callback base URL")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _resolve_callback_base_url() -> str:
    env_base = (os.environ.get("SECAMO_PUBLIC_BASE_URL") or "").strip()
    if env_base:
        return _normalize_base_url(env_base)

    hitl_endpoint = (os.environ.get("HITL_ENDPOINT_BASE_URL") or "").strip()
    if hitl_endpoint:
        return _normalize_base_url(hitl_endpoint)

    name_prefix = os.environ.get("HITL_NAME_PREFIX", "secamo-temporal-test").strip() or "secamo-temporal-test"
    parameter_name = f"/{name_prefix}/hitl/endpoint_base_url"

    ssm = boto3.client("ssm", region_name="eu-west-1")
    response = ssm.get_parameter(Name=parameter_name, WithDecryption=False)
    endpoint_value = (response.get("Parameter", {}).get("Value") or "").strip()
    if not endpoint_value:
        raise ValueError(f"Missing callback base URL in SSM parameter {parameter_name}")
    return _normalize_base_url(endpoint_value)


def _require_graph_bundle(payload: CustomerOnboardingEvent) -> dict[str, Any]:
    graph_bundle = payload.secrets.get("graph") if isinstance(payload.secrets, dict) else None
    if not isinstance(graph_bundle, dict):
        raise_activity_error(
            "customer.onboarding requires secrets.graph bundle",
            error_type="MissingGraphSecretBundle",
            non_retryable=True,
        )

    required = {"client_id", "client_secret", "tenant_azure_id"}
    missing = [key for key in sorted(required) if not str(graph_bundle.get(key) or "").strip()]
    if missing:
        raise_activity_error(
            f"customer.onboarding missing required graph secret keys: {', '.join(missing)}",
            error_type="IncompleteGraphSecretBundle",
            non_retryable=True,
        )

    return graph_bundle


@activity.defn
async def provision_customer_secrets(tenant_id: str, payload: CustomerOnboardingEvent) -> dict[str, str]:
    """Persist onboarding configuration and secret bundles into SSM paths."""
    if not tenant_id.strip():
        raise_activity_error(
            "tenant_id is required for onboarding secret provisioning",
            error_type="InvalidTenantId",
            non_retryable=True,
        )

    partial_onboarding = _is_partial_onboarding_enabled(payload)

    if not partial_onboarding:
        _require_graph_bundle(payload)

    config_values: dict[str, Any] = dict(payload.config)
    if payload.display_name and not config_values.get("display_name"):
        config_values["display_name"] = payload.display_name
    if payload.soc_analyst_email and not config_values.get("soc_analyst_email"):
        config_values["soc_analyst_email"] = payload.soc_analyst_email

    if not str(config_values.get("display_name") or "").strip():
        raise_activity_error(
            "customer.onboarding requires config.display_name or payload.display_name",
            error_type="MissingDisplayName",
            non_retryable=True,
        )

    try:
        for key, value in config_values.items():
            put_secret(
                tenant_id=tenant_id,
                path=f"config/{key}",
                value=_stringify(value),
                parameter_type="String",
                overwrite=True,
            )

        for secret_type, raw_bundle in payload.secrets.items():
            if not isinstance(raw_bundle, dict):
                continue
            for key, value in raw_bundle.items():
                put_secret(
                    tenant_id=tenant_id,
                    path=f"{secret_type}/{key}",
                    value=_stringify(value),
                    parameter_type="SecureString",
                    overwrite=True,
                )

        callback_base_url = _resolve_callback_base_url()
    except ValueError as exc:
        if partial_onboarding:
            activity.logger.warning(
                "[%s] partial onboarding enabled; callback base URL unavailable (%s). "
                "Graph subscription bootstrap will be deferred.",
                tenant_id,
                exc,
            )
            callback_base_url = ""
        else:
            raise_activity_error(
                f"[{tenant_id}] onboarding provisioning failed: {exc}",
                error_type="OnboardingInvalidConfig",
                non_retryable=True,
            )
    except (ClientError, BotoCoreError) as exc:
        raise_activity_error(
            f"[{tenant_id}] onboarding SSM write failed: {type(exc).__name__}",
            error_type="OnboardingSsmWriteFailed",
            non_retryable=False,
        )
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] onboarding provisioning failed: {type(exc).__name__}",
            error_type="OnboardingProvisioningFailed",
            non_retryable=False,
        )

    result: dict[str, str] = {
        "graph_notification_url": "",
        "partial_onboarding": "true" if partial_onboarding else "false",
    }
    if callback_base_url:
        result["graph_notification_url"] = f"{callback_base_url}/api/v1/graph/notifications/{tenant_id}"
    return result


@activity.defn
async def register_customer_tenant(tenant_id: str, payload: CustomerOnboardingEvent) -> dict[str, str]:
    """Register or upsert tenant metadata in the tenant DynamoDB table."""
    if not tenant_id.strip():
        raise_activity_error(
            "tenant_id is required for tenant registration",
            error_type="InvalidTenantId",
            non_retryable=True,
        )

    if not TENANT_TABLE_NAME:
        raise_activity_error(
            "TENANT_TABLE_NAME is not configured",
            error_type="MissingTenantTableConfig",
            non_retryable=True,
        )

    display_name = str(payload.display_name or payload.config.get("display_name") or tenant_id).strip()
    status = str(payload.config.get("status") or "active").strip().lower() or "active"
    now = datetime.now(timezone.utc).isoformat()

    table = _get_dynamodb_resource().Table(TENANT_TABLE_NAME)

    try:
        await asyncio.to_thread(
            table.put_item,
            Item={
                "tenant_id": tenant_id,
                "display_name": display_name,
                "status": status,
                "updated_at": now,
            },
        )
    except (ClientError, BotoCoreError) as exc:
        raise_activity_error(
            f"[{tenant_id}] tenant registration failed: {type(exc).__name__}",
            error_type="TenantRegistrationFailed",
            non_retryable=False,
        )
    except Exception as exc:
        raise_activity_error(
            f"[{tenant_id}] tenant registration failed: {type(exc).__name__}",
            error_type="TenantRegistrationUnexpectedError",
            non_retryable=False,
        )

    return {
        "tenant_id": tenant_id,
        "display_name": display_name,
        "status": status,
    }
