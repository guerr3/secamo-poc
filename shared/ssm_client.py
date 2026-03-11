from __future__ import annotations

import boto3

_ssm = boto3.client("ssm", region_name="eu-west-1")


def get_secret(tenant_id: str, path: str) -> str | None:
    """Read one secret from /secamo/tenants/{tenant_id}/{path}."""
    full_path = f"/secamo/tenants/{tenant_id}/{path}".replace("//", "/")
    try:
        response = _ssm.get_parameter(Name=full_path, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    except _ssm.exceptions.ParameterNotFound:
        return None


def get_secret_bundle(tenant_id: str, secret_type: str) -> dict[str, str]:
    """Read a full secret bundle from /secamo/tenants/{tenant_id}/{secret_type}/."""
    bundle_path = f"/secamo/tenants/{tenant_id}/{secret_type}/"
    response = _ssm.get_parameters_by_path(Path=bundle_path, WithDecryption=True)
    return {p["Name"].split("/")[-1]: p["Value"] for p in response.get("Parameters", [])}
