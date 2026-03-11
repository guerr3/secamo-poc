# Connectors

This package contains provider adapters used by Temporal activities to keep workflows provider-agnostic.

## Add a new connector in 5 steps

1. Create `connectors/<provider_name>.py` implementing `BaseConnector`.
2. Implement `fetch_events`, `execute_action`, and `health_check` using `httpx.AsyncClient`.
3. Use existing shared models where possible (`CanonicalEvent`, `TenantSecrets`).
4. Register the connector in `connectors/registry.py` with a stable provider key.
5. Call it from `activities/connector_dispatch.py` using the provider key in workflow input.

Notes:

- Keep secrets in `TenantSecrets` and never log them.
- Workflow code must never call connector HTTP APIs directly.

## TenantConfig Integration

Connector behavior is selected per tenant through `TenantConfig`:

- `edr_provider`: controls EDR connector lookup (`microsoft_defender`, `crowdstrike`, `sentinelone`).
- `ticketing_provider`: controls ticket connector lookup (`jira`, `halo_itsm`, `servicenow`).
- `threat_intel_providers`: controls TI fan-out connector lookups (`virustotal`, `abuseipdb`, `misp`).
- `notification_provider`: controls notification channel routing (`teams`, `slack`, `email`).

To add a new valid value for an existing provider field:

1. Implement a connector class under `connectors/`.
2. Register it in `connectors/registry.py` with the new provider key.
3. Add the new value to the corresponding `TenantConfig` literal field in `shared/models/domain.py`.
4. Add tenant config in SSM for that provider key.

SSM path conventions:

- Config path (non-sensitive): `/secamo/tenants/{tenant_id}/config/*`
- Secret path (sensitive): `/secamo/tenants/{tenant_id}/{secret_type}/*`

## Ingress Provider Routing

Generic ingress route: `POST /api/v1/ingress/event`

Routing is controlled by `PROVIDER_EVENT_ROUTING` in `terraform/modules/ingress/src/ingress/handler.py`.
To add a new provider event mapping:

1. Add `(provider, event_type): (workflow_name, task_queue)` in `PROVIDER_EVENT_ROUTING`.
2. Add a normalizer in `terraform/modules/ingress/src/ingress/mappers.py`.
3. Register the normalizer in `_NORMALIZERS`.
4. Ensure workflow input includes `source_provider`.

Normalizer pattern:

- `normalize_event_body(provider, event_type, tenant_id, raw_body)` is pure and has no I/O.
- If no normalizer is found, payload is passed through best-effort with `source_provider` and `tenant_id` injected.

Trust boundary rule:

- `tenant_id` must always come from authorizer context (`event.tenant_id`), never from webhook body.

Local curl examples:

```bash
curl -X POST http://localhost:9000/api/v1/ingress/event \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-demo-001" \
  -d '{"provider":"microsoft_defender","event_type":"alert","id":"a-1","severity":"high","title":"Alert"}'
```

```bash
curl -X POST http://localhost:9000/api/v1/ingress/event \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-demo-001" \
  -d '{"provider":"crowdstrike","event_type":"detection_summary","detection":{"CompositeID":"cs-1","Severity":"critical","Name":"Detection"}}'
```

```bash
curl -X POST http://localhost:9000/api/v1/ingress/event \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-demo-001" \
  -d '{"provider":"sentinelone","event_type":"alert","data":{"id":"s1-1","severity":"medium","threatName":"Threat"}}'
```

```bash
curl -X POST http://localhost:9000/api/v1/ingress/event \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-demo-001" \
  -d '{"provider":"jira","event_type":"jira:issue_created","issue":{"key":"IAM-1","fields":{"customfield_employee_email":"new.user@example.com","customfield_department":"Engineering","customfield_role":"Developer"}}}'
```
