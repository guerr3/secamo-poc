# Temporal UI Testing Payloads (Current)

These payloads reflect the current orchestration model after SOC route cutover to `CaseIntakeWorkflow`.

Use each payload as workflow Input in Temporal UI.
Temporal UI expects workflow arguments as a JSON array, so every example is wrapped in `[...]`.

## Workflow Order For End-to-End Validation

1. `CustomerOnboardingWorkflow` (queue: `user-lifecycle`)
2. `PollingBootstrapWorkflow` (queue: `polling`)
3. `IamOnboardingWorkflow` (queue: `user-lifecycle`)
4. `CaseIntakeWorkflow` with `defender.alert` payload (queue: `edr`)
5. `CaseIntakeWorkflow` with `defender.impossible_travel` payload (queue: `edr`)
6. `CaseIntakeWorkflow` with `defender.security_signal` payload (queue: `edr`)

Optional direct workflow tests are still possible for legacy/manual paths:

- `DefenderAlertEnrichmentWorkflow`
- `ImpossibleTravelWorkflow`
- `GenericSecuritySignalWorkflow`

## Reusable Values

Use placeholders and replace per environment:

- `<TENANT_ID>`
- `<TIMESTAMP_ISO8601>`
- `<REQUESTER>`
- `<ALERT_ID>`
- `<USER_EMAIL>`
- `<DEVICE_ID>`

Do not put production secrets or real API tokens in this file.

## 1) CustomerOnboardingWorkflow

Task Queue: `user-lifecycle`

```json
[
  {
    "event_id": "evt-onboarding-001",
    "tenant_id": "<TENANT_ID>",
    "source_provider": "internal-api",
    "event_name": "customer.onboarding",
    "schema_version": "1.0.0",
    "event_version": "1.0.0",
    "ocsf_version": "1.1.0",
    "occurred_at": "<TIMESTAMP_ISO8601>",
    "correlation": {
      "correlation_id": "corr-onboarding-001",
      "causation_id": "corr-onboarding-001",
      "request_id": "req-onboarding-001",
      "trace_id": "trace-onboarding-001",
      "storage_partition": {
        "ddb_pk": "TENANT#<TENANT_ID>",
        "ddb_sk": "EVENT#customer#onboarding#evt-onboarding-001",
        "s3_bucket": "secamo-events-<TENANT_ID>",
        "s3_key_prefix": "raw/customer.onboarding/evt-onboarding-001"
      }
    },
    "payload": {
      "event_type": "customer.onboarding",
      "activity_id": 1,
      "activity_name": "create",
      "tenant_id": "<TENANT_ID>",
      "display_name": "Tenant Demo",
      "action": "create",
      "config": {
        "iam_provider": "microsoft_graph",
        "edr_provider": "microsoft_defender",
        "ticketing_provider": "jira",
        "threat_intel_providers": "virustotal,abuseipdb",
        "polling_providers": "microsoft_defender:defender_alerts:graph:300,microsoft_defender:entra_signin_logs:graph:300",
        "graph_subscriptions": "security/alerts_v2:created+updated:false:24"
      },
      "secrets": {
        "graph": {
          "client_id": "<GRAPH_CLIENT_ID>",
          "client_secret": "<GRAPH_CLIENT_SECRET>",
          "tenant_azure_id": "<GRAPH_TENANT_ID>"
        },
        "ticketing": {
          "jira_base_url": "https://<ORG>.atlassian.net",
          "jira_email": "<JIRA_EMAIL>",
          "jira_api_token": "<JIRA_API_TOKEN>",
          "project_key": "SOC",
          "project_type": "jsm"
        },
        "threatintel": {
          "virustotal_api_key": "<VT_API_KEY>",
          "abuseipdb_api_key": "<ABUSEIPDB_API_KEY>"
        }
      },
      "soc_analyst_email": "soc@secamo.local",
      "welcome_email": "owner@tenant.local"
    },
    "metadata": {
      "requester": "<REQUESTER>"
    }
  }
]
```

## 2) PollingBootstrapWorkflow

Task Queue: `polling`

```json
[
  {
    "tenant_id": "<TENANT_ID>"
  }
]
```

## 3) IamOnboardingWorkflow (create)

Task Queue: `user-lifecycle`

```json
[
  {
    "event_id": "evt-iam-create-001",
    "tenant_id": "<TENANT_ID>",
    "source_provider": "internal-api",
    "event_name": "iam.onboarding",
    "schema_version": "1.0.0",
    "event_version": "1.0.0",
    "ocsf_version": "1.1.0",
    "occurred_at": "<TIMESTAMP_ISO8601>",
    "correlation": {
      "correlation_id": "corr-iam-001",
      "causation_id": "corr-iam-001",
      "request_id": "req-iam-001",
      "trace_id": "trace-iam-001"
    },
    "payload": {
      "event_type": "iam.onboarding",
      "activity_id": 3001,
      "activity_name": "create",
      "user_email": "<USER_EMAIL>",
      "action": "create",
      "user_data": {
        "email": "<USER_EMAIL>",
        "first_name": "Alice",
        "last_name": "Blue",
        "department": "Security",
        "role": "Analyst",
        "license_sku": "M365-E5"
      }
    },
    "metadata": {
      "requester": "<REQUESTER>"
    }
  }
]
```

## 4) CaseIntakeWorkflow - defender.alert

Task Queue: `edr`

```json
[
  {
    "event_id": "evt-defender-alert-001",
    "tenant_id": "<TENANT_ID>",
    "source_provider": "microsoft_defender",
    "event_name": "defender.alert",
    "schema_version": "1.0.0",
    "event_version": "1.0.0",
    "ocsf_version": "1.1.0",
    "occurred_at": "<TIMESTAMP_ISO8601>",
    "payload": {
      "event_type": "defender.alert",
      "activity_id": 2004,
      "activity_name": "create",
      "alert_id": "<ALERT_ID>",
      "title": "Suspicious sign-in",
      "description": "Automated test alert",
      "severity_id": 60,
      "severity": "high",
      "status": "open",
      "vendor_extensions": {
        "user_email": {
          "source": "microsoft_defender",
          "value": "<USER_EMAIL>"
        },
        "device_id": { "source": "microsoft_defender", "value": "<DEVICE_ID>" },
        "source_ip": { "source": "microsoft_defender", "value": "8.8.8.8" }
      }
    },
    "metadata": {
      "requester": "<REQUESTER>",
      "provider_event_id": "<ALERT_ID>"
    }
  }
]
```

## 5) CaseIntakeWorkflow - defender.impossible_travel

Task Queue: `edr`

```json
[
  {
    "event_id": "evt-impossible-travel-001",
    "tenant_id": "<TENANT_ID>",
    "source_provider": "microsoft_defender",
    "event_name": "defender.impossible_travel",
    "schema_version": "1.0.0",
    "event_version": "1.0.0",
    "ocsf_version": "1.1.0",
    "occurred_at": "<TIMESTAMP_ISO8601>",
    "payload": {
      "event_type": "defender.impossible_travel",
      "activity_id": 3002,
      "activity_name": "detect",
      "user_principal_name": "<USER_EMAIL>",
      "source_ip": "8.8.4.4",
      "destination_ip": "1.0.0.1",
      "location": "EU",
      "severity_id": 60,
      "severity": "high",
      "message": "Impossible travel detected"
    },
    "metadata": {
      "requester": "<REQUESTER>"
    }
  }
]
```

## 6) CaseIntakeWorkflow - defender.security_signal

Task Queue: `edr`

```json
[
  {
    "event_id": "evt-security-signal-001",
    "tenant_id": "<TENANT_ID>",
    "source_provider": "microsoft_defender",
    "event_name": "defender.security_signal",
    "schema_version": "1.0.0",
    "event_version": "1.0.0",
    "ocsf_version": "1.1.0",
    "occurred_at": "<TIMESTAMP_ISO8601>",
    "payload": {
      "event_type": "defender.security_signal",
      "activity_id": 2010,
      "activity_name": "observe",
      "signal_id": "signal-001",
      "title": "Risky user update",
      "description": "Risk state changed",
      "resource_type": "identityProtection/riskyUsers",
      "provider_event_type": "risky_user",
      "severity_id": 45,
      "severity": "medium",
      "status": "open"
    },
    "metadata": {
      "requester": "<REQUESTER>",
      "provider_event_id": "signal-001"
    }
  }
]
```

## Local File References

Repository examples you can adapt:

- `onboarding-tenant-demo-001.json`
- `payload.json`
- `polling_payload.json`
