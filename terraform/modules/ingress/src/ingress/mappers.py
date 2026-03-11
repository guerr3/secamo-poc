from __future__ import annotations

from typing import Any, Callable


def _coerce_severity(value: Any, default: str = "medium") -> str:
    if value is None:
        return default
    return str(value).strip().lower() or default


def _split_name(full_name: str) -> tuple[str, str]:
    parts = (full_name or "").strip().split(" ")
    if not parts:
        return "Unknown", "User"
    if len(parts) == 1:
        return parts[0], "User"
    return parts[0], " ".join(parts[1:])


def _normalize_ms_defender_alert(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    alert = raw_body.get("alert", raw_body)
    return {
        "tenant_id": tenant_id,
        "source_provider": provider,
        "requester": raw_body.get("requester", "ingress-api"),
        "alert": {
            "alert_id": alert.get("alert_id") or alert.get("id") or "unknown-alert",
            "severity": _coerce_severity(alert.get("severity")),
            "title": alert.get("title", "Security alert"),
            "description": alert.get("description", ""),
            "device_id": alert.get("device_id") or alert.get("deviceId"),
            "user_email": alert.get("user_email") or alert.get("userPrincipalName"),
            "source_ip": alert.get("source_ip") or alert.get("sourceIp") or alert.get("ipAddress"),
            "destination_ip": alert.get("destination_ip") or alert.get("destinationIp"),
        },
    }


def _normalize_ms_defender_impossible_travel(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    alert_payload = _normalize_ms_defender_alert(tenant_id, raw_body, provider)
    alert = alert_payload["alert"]
    return {
        "tenant_id": tenant_id,
        "source_provider": provider,
        "requester": raw_body.get("requester", "ingress-api"),
        "alert": alert,
        "user_email": alert.get("user_email") or raw_body.get("user_email") or "unknown@example.com",
        "source_ip": alert.get("source_ip") or raw_body.get("source_ip") or "0.0.0.0",
        "destination_ip": alert.get("destination_ip") or raw_body.get("destination_ip") or "0.0.0.0",
    }


def _normalize_crowdstrike_detection_summary(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    detection = raw_body.get("detection", raw_body)
    return {
        "tenant_id": tenant_id,
        "source_provider": provider,
        "requester": raw_body.get("requester", "ingress-api"),
        "alert": {
            "alert_id": detection.get("CompositeID") or detection.get("composite_id") or "unknown-detection",
            "severity": _coerce_severity(detection.get("Severity"), default="high"),
            "title": detection.get("Name") or detection.get("Title") or "CrowdStrike Detection",
            "description": detection.get("Description") or detection.get("description") or "",
            "device_id": detection.get("DeviceId") or detection.get("device_id"),
            "user_email": detection.get("UserName") or detection.get("user_email"),
            "source_ip": detection.get("LocalIP") or detection.get("source_ip"),
            "destination_ip": detection.get("RemoteIP") or detection.get("destination_ip"),
        },
    }


def _normalize_crowdstrike_impossible_travel(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    alert_payload = _normalize_crowdstrike_detection_summary(tenant_id, raw_body, provider)
    alert = alert_payload["alert"]
    return {
        "tenant_id": tenant_id,
        "source_provider": provider,
        "requester": raw_body.get("requester", "ingress-api"),
        "alert": alert,
        "user_email": alert.get("user_email") or "unknown@example.com",
        "source_ip": alert.get("source_ip") or "0.0.0.0",
        "destination_ip": alert.get("destination_ip") or "0.0.0.0",
    }


def _normalize_sentinelone_alert(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    alert = raw_body.get("data", raw_body)
    return {
        "tenant_id": tenant_id,
        "source_provider": provider,
        "requester": raw_body.get("requester", "ingress-api"),
        "alert": {
            "alert_id": alert.get("id") or alert.get("alert_id") or "unknown-alert",
            "severity": _coerce_severity(alert.get("severity"), default="medium"),
            "title": alert.get("threatName") or alert.get("title") or "SentinelOne Alert",
            "description": alert.get("description") or "",
            "device_id": alert.get("agentUuid") or alert.get("device_id"),
            "user_email": alert.get("user") or alert.get("user_email"),
            "source_ip": alert.get("srcIp") or alert.get("source_ip"),
            "destination_ip": alert.get("dstIp") or alert.get("destination_ip"),
        },
    }


def _normalize_jira_issue_created(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    issue = raw_body.get("issue", {})
    fields = issue.get("fields", {})
    reporter = fields.get("reporter", {}) if isinstance(fields.get("reporter"), dict) else {}

    employee_email = fields.get("customfield_employee_email") or fields.get("employee_email") or "unknown@example.com"
    display_name = fields.get("customfield_employee_name") or fields.get("employee_name") or employee_email.split("@")[0]
    first_name, last_name = _split_name(str(display_name))

    return {
        "tenant_id": tenant_id,
        "source_provider": provider,
        "action": fields.get("customfield_lifecycle_action") or raw_body.get("action") or "create",
        "user_data": {
            "email": employee_email,
            "first_name": first_name,
            "last_name": last_name,
            "department": fields.get("customfield_department") or "Security",
            "role": fields.get("customfield_role") or "User",
            "manager_email": fields.get("customfield_manager_email"),
            "license_sku": fields.get("customfield_license_sku"),
        },
        "requester": reporter.get("emailAddress") or reporter.get("displayName") or raw_body.get("requester") or "ingress-api",
        "ticket_id": issue.get("key") or raw_body.get("ticket_id") or "",
    }


def _normalize_jira_issue_updated(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    payload = _normalize_jira_issue_created(tenant_id, raw_body, provider)
    if payload.get("action") == "create":
        payload["action"] = "update"
    return payload


NormalizerFn = Callable[[str, dict[str, Any], str], dict[str, Any]]

_NORMALIZERS: dict[tuple[str, str], NormalizerFn] = {
    ("microsoft_defender", "alert"): _normalize_ms_defender_alert,
    ("microsoft_defender", "impossible_travel"): _normalize_ms_defender_impossible_travel,
    ("crowdstrike", "detection_summary"): _normalize_crowdstrike_detection_summary,
    ("crowdstrike", "impossible_travel"): _normalize_crowdstrike_impossible_travel,
    ("sentinelone", "alert"): _normalize_sentinelone_alert,
    ("jira", "jira:issue_created"): _normalize_jira_issue_created,
    ("jira", "jira:issue_updated"): _normalize_jira_issue_updated,
    ("microsoft_graph", "iam_request"): lambda tenant_id, raw_body, provider: {
        "tenant_id": tenant_id,
        "source_provider": provider,
        "action": raw_body.get("action", "create"),
        "user_data": raw_body.get("user_data", {}),
        "requester": raw_body.get("requester", "ingress-api"),
        "ticket_id": raw_body.get("ticket_id", ""),
    },
}


def normalize_event_body(provider: str, event_type: str, tenant_id: str, raw_body: dict[str, Any]) -> dict[str, Any]:
    """Normalize provider webhook payloads into workflow input shapes."""
    key = (provider, event_type)
    normalizer = _NORMALIZERS.get(key)
    if normalizer is None:
        passthrough = dict(raw_body)
        passthrough["source_provider"] = provider
        passthrough["tenant_id"] = tenant_id
        return passthrough

    payload = normalizer(tenant_id=tenant_id, raw_body=raw_body, provider=provider)
    payload["source_provider"] = provider
    payload["tenant_id"] = tenant_id
    return payload
