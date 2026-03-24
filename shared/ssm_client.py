from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

_ssm = None


def _get_ssm_client():
    global _ssm
    if _ssm is None:
        _ssm = boto3.client("ssm", region_name="eu-west-1")
    return _ssm


def get_secret(tenant_id: str, path: str) -> str | None:
    """Read one secret from /secamo/tenants/{tenant_id}/{path}."""
    full_path = f"/secamo/tenants/{tenant_id}/{path}".replace("//", "/")
    ssm = _get_ssm_client()
    try:
        response = ssm.get_parameter(Name=full_path, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code == "ParameterNotFound":
            return None
        raise


def get_secret_bundle(tenant_id: str, secret_type: str) -> dict[str, str]:
    """Read a full secret bundle from /secamo/tenants/{tenant_id}/{secret_type}/."""
    bundle_path = f"/secamo/tenants/{tenant_id}/{secret_type}/"
    ssm = _get_ssm_client()
    response = ssm.get_parameters_by_path(Path=bundle_path, WithDecryption=True)
    bundle = {p["Name"].split("/")[-1]: p["Value"] for p in response.get("Parameters", [])}

    next_token = response.get("NextToken")
    while next_token:
        response = ssm.get_parameters_by_path(
            Path=bundle_path,
            WithDecryption=True,
            NextToken=next_token,
        )
        bundle.update({p["Name"].split("/")[-1]: p["Value"] for p in response.get("Parameters", [])})
        next_token = response.get("NextToken")

    return bundle


def put_secret(
    tenant_id: str,
    path: str,
    value: str,
    *,
    parameter_type: str = "SecureString",
    overwrite: bool = True,
) -> None:
    """Persist one value at /secamo/tenants/{tenant_id}/{path}."""
    full_path = f"/secamo/tenants/{tenant_id}/{path}".replace("//", "/")
    ssm = _get_ssm_client()
    ssm.put_parameter(
        Name=full_path,
        Value=value,
        Type=parameter_type,
        Overwrite=overwrite,
    )


def put_secret_bundle(
    tenant_id: str,
    secret_type: str,
    values: dict[str, str],
    *,
    parameter_type: str = "SecureString",
    overwrite: bool = True,
) -> None:
    """Persist multiple values under /secamo/tenants/{tenant_id}/{secret_type}/."""
    for key, value in values.items():
        put_secret(
            tenant_id=tenant_id,
            path=f"{secret_type}/{key}",
            value=value,
            parameter_type=parameter_type,
            overwrite=overwrite,
        )
