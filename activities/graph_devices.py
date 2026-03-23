from __future__ import annotations

from urllib.parse import quote

import httpx
from temporalio import activity

from activities._activity_errors import application_error_from_http_status
from shared.graph_client import get_defender_token, get_graph_token
from shared.models import ConnectorActionResult, DeviceDetail, TenantSecrets

DEFENDER_BASE = "https://api.security.microsoft.com/api"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _handle_http_error(tenant_id: str, provider: str, status: int, action: str) -> None:
    if status >= 400:
        raise application_error_from_http_status(tenant_id, provider, action, status)


@activity.defn
async def graph_isolate_device(tenant_id: str, device_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_isolate_device: {device_id}")
    token = await get_defender_token(secrets)
    payload = {"Comment": "Isolated by Secamo orchestrator", "IsolationType": "Full"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{DEFENDER_BASE}/machines/{quote(device_id)}/isolate",
            headers=_auth_headers(token),
            json=payload,
        )

    if response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_defender", response.status_code, "graph_isolate_device")
    return response.status_code == 201


@activity.defn
async def graph_unisolate_device(tenant_id: str, device_id: str, secrets: TenantSecrets) -> bool:
    activity.logger.info(f"[{tenant_id}] graph_unisolate_device: {device_id}")
    token = await get_defender_token(secrets)
    payload = {"Comment": "Released from isolation by Secamo orchestrator"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{DEFENDER_BASE}/machines/{quote(device_id)}/unisolate",
            headers=_auth_headers(token),
            json=payload,
        )

    if response.status_code == 404:
        return False
    _handle_http_error(tenant_id, "microsoft_defender", response.status_code, "graph_unisolate_device")
    return response.status_code == 201


@activity.defn
async def graph_get_device_details(tenant_id: str, device_id: str, secrets: TenantSecrets) -> DeviceDetail | None:
    activity.logger.info(f"[{tenant_id}] graph_get_device_details: {device_id}")
    token = await get_defender_token(secrets)

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{DEFENDER_BASE}/machines/{quote(device_id)}",
            headers=_auth_headers(token),
        )

    if response.status_code == 404:
        return None
    _handle_http_error(tenant_id, "microsoft_defender", response.status_code, "graph_get_device_details")
    if response.status_code != 200:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_defender",
            "graph_get_device_details",
            response.status_code,
        )

    body = response.json()
    return DeviceDetail(
        id=body.get("id", device_id),
        computerDnsName=body.get("computerDnsName"),
        firstSeen=body.get("firstSeen"),
        lastSeen=body.get("lastSeen"),
        osPlatform=body.get("osPlatform"),
        version=body.get("version"),
        osProcessor=body.get("osProcessor"),
        lastIpAddress=body.get("lastIpAddress"),
        lastExternalIpAddress=body.get("lastExternalIpAddress"),
        osBuild=body.get("osBuild"),
        healthStatus=body.get("healthStatus"),
        rbacGroupId=body.get("rbacGroupId"),
        rbacGroupName=body.get("rbacGroupName"),
        riskScore=body.get("riskScore"),
        exposureLevel=body.get("exposureLevel"),
        isAadJoined=body.get("isAadJoined"),
        aadDeviceId=body.get("aadDeviceId"),
        machineTags=body.get("machineTags") or [],
    )


@activity.defn
async def graph_run_antivirus_scan(
    tenant_id: str,
    device_id: str,
    secrets: TenantSecrets,
    scan_type: str = "Quick",
) -> ConnectorActionResult:
    activity.logger.info(f"[{tenant_id}] graph_run_antivirus_scan: {device_id}")
    token = await get_defender_token(secrets)
    normalized_scan = "Full" if str(scan_type).lower() == "full" else "Quick"
    payload = {
        "Comment": f"Secamo orchestrator {normalized_scan.lower()} antivirus scan",
        "ScanType": normalized_scan,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{DEFENDER_BASE}/machines/{quote(device_id)}/runAntiVirusScan",
            headers=_auth_headers(token),
            json=payload,
        )

    if response.status_code == 404:
        return ConnectorActionResult(
            provider="microsoft_defender",
            action="run_antivirus_scan",
            success=False,
            details="device not found",
            data={"device_id": device_id, "scan_type": normalized_scan},
        )

    _handle_http_error(tenant_id, "microsoft_defender", response.status_code, "graph_run_antivirus_scan")
    if response.status_code != 201:
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_defender",
            "graph_run_antivirus_scan",
            response.status_code,
        )

    return ConnectorActionResult(
        provider="microsoft_defender",
        action="run_antivirus_scan",
        success=True,
        details="scan action submitted",
        data=response.json(),
    )


@activity.defn
async def graph_list_noncompliant_devices(tenant_id: str, secrets: TenantSecrets) -> list[dict]:
    activity.logger.info(f"[{tenant_id}] graph_list_noncompliant_devices")
    graph_token = await get_graph_token(secrets)
    filter_q = quote("complianceState eq 'noncompliant'")
    select_q = quote(
        "id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,lastSyncDateTime,azureADDeviceId"
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{GRAPH_BASE}/deviceManagement/managedDevices?$filter={filter_q}&$select={select_q}&$top=200",
            headers=_auth_headers(graph_token),
        )

    if response.status_code != 200:
        _handle_http_error(tenant_id, "microsoft_graph", response.status_code, "graph_list_noncompliant_devices")
        raise application_error_from_http_status(
            tenant_id,
            "microsoft_graph",
            "graph_list_noncompliant_devices",
            response.status_code,
        )

    return response.json().get("value", [])