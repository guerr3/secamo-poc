from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_mappers_module():
    mapper_path = Path(__file__).resolve().parents[1] / "terraform" / "modules" / "ingress" / "src" / "ingress" / "mappers.py"
    spec = importlib.util.spec_from_file_location("ingress_mappers", mapper_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_normalize_microsoft_defender_alert() -> None:
    mappers = _load_mappers_module()
    payload = mappers.normalize_event_body(
        provider="microsoft_defender",
        event_type="alert",
        tenant_id="tenant-demo-001",
        raw_body={
            "id": "md-001",
            "severity": "HIGH",
            "title": "Impossible travel",
            "description": "Suspicious sign-in",
            "deviceId": "dev-1",
            "userPrincipalName": "alice@example.com",
            "ipAddress": "10.1.1.2",
        },
    )

    assert payload["tenant_id"] == "tenant-demo-001"
    assert payload["source_provider"] == "microsoft_defender"
    assert payload["alert"]["alert_id"] == "md-001"
    assert payload["alert"]["severity"] == "high"


def test_normalize_crowdstrike_detection_summary() -> None:
    mappers = _load_mappers_module()
    payload = mappers.normalize_event_body(
        provider="crowdstrike",
        event_type="detection_summary",
        tenant_id="tenant-demo-001",
        raw_body={
            "detection": {
                "CompositeID": "cs-111",
                "Severity": "Critical",
                "Name": "Credential dumping",
                "Description": "LSASS memory access",
                "DeviceId": "host-77",
                "UserName": "bob@example.com",
                "LocalIP": "10.2.2.2",
                "RemoteIP": "8.8.8.8",
            }
        },
    )

    assert payload["source_provider"] == "crowdstrike"
    assert payload["alert"]["alert_id"] == "cs-111"
    assert payload["alert"]["title"] == "Credential dumping"


def test_normalize_jira_issue_created() -> None:
    mappers = _load_mappers_module()
    payload = mappers.normalize_event_body(
        provider="jira",
        event_type="jira:issue_created",
        tenant_id="tenant-demo-001",
        raw_body={
            "issue": {
                "key": "IAM-42",
                "fields": {
                    "customfield_employee_email": "jane@example.com",
                    "customfield_employee_name": "Jane Doe",
                    "customfield_department": "Engineering",
                    "customfield_role": "Developer",
                    "customfield_lifecycle_action": "create",
                    "reporter": {"emailAddress": "manager@example.com"},
                },
            }
        },
    )

    assert payload["tenant_id"] == "tenant-demo-001"
    assert payload["source_provider"] == "jira"
    assert payload["ticket_id"] == "IAM-42"
    assert payload["user_data"]["email"] == "jane@example.com"
    assert payload["action"] == "create"


def test_normalize_sentinelone_alert() -> None:
    mappers = _load_mappers_module()
    payload = mappers.normalize_event_body(
        provider="sentinelone",
        event_type="alert",
        tenant_id="tenant-demo-001",
        raw_body={
            "data": {
                "id": "s1-8",
                "severity": "MEDIUM",
                "threatName": "Suspicious PowerShell",
                "description": "Encoded command observed",
                "agentUuid": "agent-9",
                "user": "carol@example.com",
                "srcIp": "10.9.9.9",
                "dstIp": "104.18.0.1",
            }
        },
    )

    assert payload["source_provider"] == "sentinelone"
    assert payload["alert"]["alert_id"] == "s1-8"
    assert payload["alert"]["title"] == "Suspicious PowerShell"
