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


def _build_security_event(
    *,
    event_id: str,
    event_type: str,
    tenant_id: str,
    provider: str,
    requester: str,
    severity: str | None = None,
    correlation_id: str | None = None,
    ticket_id: str | None = None,
    alert: dict[str, Any] | None = None,
    user: dict[str, Any] | None = None,
    device: dict[str, Any] | None = None,
    network: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "tenant_id": tenant_id,
        "source_provider": provider,
        "requester": requester,
        "severity": severity,
        "correlation_id": correlation_id,
        "ticket_id": ticket_id,
        "alert": alert,
        "user": user,
        "device": device,
        "network": network,
        "metadata": metadata or {},
    }


def _normalize_ms_defender_alert(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    alert_src = raw_body.get("alert", raw_body)
    alert = {
        "alert_id": alert_src.get("alert_id") or alert_src.get("id") or "unknown-alert",
        "severity": _coerce_severity(alert_src.get("severity")),
        "title": alert_src.get("title", "Security alert"),
        "description": alert_src.get("description", ""),
        "device_id": alert_src.get("device_id") or alert_src.get("deviceId"),
        "user_email": alert_src.get("user_email") or alert_src.get("userPrincipalName"),
        "source_ip": alert_src.get("source_ip") or alert_src.get("sourceIp") or alert_src.get("ipAddress"),
        "destination_ip": alert_src.get("destination_ip") or alert_src.get("destinationIp"),
    }
    return _build_security_event(
        event_id=alert["alert_id"],
        event_type="defender.alert",
        tenant_id=tenant_id,
        provider=provider,
        requester=raw_body.get("requester", "ingress-api"),
        severity=alert["severity"],
        alert=alert,
        user={"user_principal_name": alert.get("user_email")},
        device={"device_id": alert.get("device_id")},
        network={
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
        },
    )


def _normalize_ms_defender_impossible_travel(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    payload = _normalize_ms_defender_alert(tenant_id, raw_body, provider)
    payload["event_type"] = "defender.impossible_travel"
    payload["user"] = {
        "user_principal_name": payload.get("alert", {}).get("user_email")
        or raw_body.get("user_email")
        or "unknown@example.com"
    }
    payload["network"] = {
        "source_ip": payload.get("alert", {}).get("source_ip") or raw_body.get("source_ip") or "0.0.0.0",
        "destination_ip": payload.get("alert", {}).get("destination_ip") or raw_body.get("destination_ip") or "0.0.0.0",
    }
    return payload


def _normalize_crowdstrike_detection_summary(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    detection = raw_body.get("detection", raw_body)
    alert = {
        "alert_id": detection.get("CompositeID") or detection.get("composite_id") or "unknown-detection",
        "severity": _coerce_severity(detection.get("Severity"), default="high"),
        "title": detection.get("Name") or detection.get("Title") or "CrowdStrike Detection",
        "description": detection.get("Description") or detection.get("description") or "",
        "device_id": detection.get("DeviceId") or detection.get("device_id"),
        "user_email": detection.get("UserName") or detection.get("user_email"),
        "source_ip": detection.get("LocalIP") or detection.get("source_ip"),
        "destination_ip": detection.get("RemoteIP") or detection.get("destination_ip"),
    }
    return _build_security_event(
        event_id=alert["alert_id"],
        event_type="defender.alert",
        tenant_id=tenant_id,
        provider=provider,
        requester=raw_body.get("requester", "ingress-api"),
        severity=alert["severity"],
        alert=alert,
        user={"user_principal_name": alert.get("user_email")},
        device={"device_id": alert.get("device_id")},
        network={
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
        },
    )


def _normalize_crowdstrike_impossible_travel(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    payload = _normalize_crowdstrike_detection_summary(tenant_id, raw_body, provider)
    payload["event_type"] = "defender.impossible_travel"
    payload["user"] = {
        "user_principal_name": payload.get("alert", {}).get("user_email") or "unknown@example.com"
    }
    payload["network"] = {
        "source_ip": payload.get("alert", {}).get("source_ip") or "0.0.0.0",
        "destination_ip": payload.get("alert", {}).get("destination_ip") or "0.0.0.0",
    }
    return payload


def _normalize_sentinelone_alert(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    alert_src = raw_body.get("data", raw_body)
    alert = {
        "alert_id": alert_src.get("id") or alert_src.get("alert_id") or "unknown-alert",
        "severity": _coerce_severity(alert_src.get("severity"), default="medium"),
        "title": alert_src.get("threatName") or alert_src.get("title") or "SentinelOne Alert",
        "description": alert_src.get("description") or "",
        "device_id": alert_src.get("agentUuid") or alert_src.get("device_id"),
        "user_email": alert_src.get("user") or alert_src.get("user_email"),
        "source_ip": alert_src.get("srcIp") or alert_src.get("source_ip"),
        "destination_ip": alert_src.get("dstIp") or alert_src.get("destination_ip"),
    }
    return _build_security_event(
        event_id=alert["alert_id"],
        event_type="defender.alert",
        tenant_id=tenant_id,
        provider=provider,
        requester=raw_body.get("requester", "ingress-api"),
        severity=alert["severity"],
        alert=alert,
        user={"user_principal_name": alert.get("user_email")},
        device={"device_id": alert.get("device_id")},
        network={
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
        },
    )


def _normalize_jira_issue_created(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    issue = raw_body.get("issue", {})
    fields = issue.get("fields", {})
    reporter = fields.get("reporter", {}) if isinstance(fields.get("reporter"), dict) else {}

    employee_email = fields.get("customfield_employee_email") or fields.get("employee_email") or "unknown@example.com"
    display_name = fields.get("customfield_employee_name") or fields.get("employee_name") or employee_email.split("@")[0]
    first_name, last_name = _split_name(str(display_name))

    ticket_id = issue.get("key") or raw_body.get("ticket_id") or ""
    user_data = {
        "email": employee_email,
        "first_name": first_name,
        "last_name": last_name,
        "department": fields.get("customfield_department") or "Security",
        "role": fields.get("customfield_role") or "User",
        "manager_email": fields.get("customfield_manager_email"),
        "license_sku": fields.get("customfield_license_sku"),
    }
    action = fields.get("customfield_lifecycle_action") or raw_body.get("action") or "create"
    return _build_security_event(
        event_id=ticket_id or f"jira-{tenant_id}",
        event_type="iam.onboarding",
        tenant_id=tenant_id,
        provider=provider,
        requester=reporter.get("emailAddress") or reporter.get("displayName") or raw_body.get("requester") or "ingress-api",
        ticket_id=ticket_id,
        user={
            "user_principal_name": employee_email,
            "action": action,
            "user_data": user_data,
        },
    )


def _normalize_jira_issue_updated(tenant_id: str, raw_body: dict[str, Any], provider: str) -> dict[str, Any]:
    payload = _normalize_jira_issue_created(tenant_id, raw_body, provider)
    if payload.get("user", {}).get("action") == "create":
        payload["user"]["action"] = "update"
    return payload


NormalizerFn = Callable[[str, dict[str, Any], str], dict[str, Any]]

_NORMALIZERS: dict[tuple[str, str], NormalizerFn] = {
    ("microsoft_defender", "alert"): _normalize_ms_defender_alert,
    ("microsoft_defender", "impossible_travel"): _normalize_ms_defender_impossible_travel,
    ("microsoft_graph", "defender.alert"): _normalize_ms_defender_alert,
    ("microsoft_graph", "defender.impossible_travel"): _normalize_ms_defender_impossible_travel,
    ("crowdstrike", "detection_summary"): _normalize_crowdstrike_detection_summary,
    ("crowdstrike", "impossible_travel"): _normalize_crowdstrike_impossible_travel,
    ("sentinelone", "alert"): _normalize_sentinelone_alert,
    ("jira", "jira:issue_created"): _normalize_jira_issue_created,
    ("jira", "jira:issue_updated"): _normalize_jira_issue_updated,
    ("microsoft_graph", "iam_request"): lambda tenant_id, raw_body, provider: {
        "event_id": raw_body.get("request_id") or raw_body.get("ticket_id") or f"iam-{tenant_id}",
        "event_type": "iam.onboarding",
        "tenant_id": tenant_id,
        "source_provider": provider,
        "requester": raw_body.get("requester", "ingress-api"),
        "severity": None,
        "correlation_id": raw_body.get("correlation_id"),
        "ticket_id": raw_body.get("ticket_id", ""),
        "alert": None,
        "user": {
            "user_principal_name": (raw_body.get("user_data") or {}).get("email"),
            "action": raw_body.get("action", "create"),
            "user_data": raw_body.get("user_data", {}),
        },
        "device": None,
        "network": None,
        "metadata": {},
    },
}


def normalize_event_body(provider: str, event_type: str, tenant_id: str, raw_body: dict[str, Any]) -> dict[str, Any]:
    """Normalize provider webhook payloads into intermediate envelope-build input shape."""

    key = (provider, event_type)
    normalizer = _NORMALIZERS.get(key)
    if normalizer is None:
        fallback_event_id = (
            raw_body.get("event_id")
            or raw_body.get("id")
            or raw_body.get("correlation_id")
            or raw_body.get("request_id")
        )
        if not fallback_event_id:
            # Deterministic hash composite to avoid dedup collisions.
            import hashlib
            import json as _json

            seed = {
                "provider": provider,
                "tenant_id": tenant_id,
                "event_type": event_type,
                "body": raw_body,
            }
            canonical = _json.dumps(seed, sort_keys=True, separators=(",", ":"), default=str)
            fallback_event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        return _build_security_event(
            event_id=fallback_event_id,
            event_type=event_type,
            tenant_id=tenant_id,
            provider=provider,
            requester=raw_body.get("requester", "ingress-api"),
            severity=_coerce_severity(raw_body.get("severity")),
            metadata=dict(raw_body),
        )

    return normalizer(tenant_id=tenant_id, raw_body=raw_body, provider=provider)
