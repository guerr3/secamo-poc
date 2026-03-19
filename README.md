# Secamo Process Orchestrator

## 1. Project Overview

Secamo is a multi-tenant security automation orchestrator for MSSP teams that standardizes IAM and SOC response workflows across client environments. It is designed for security engineers operating managed tenants and ops engineers deploying tenant-specific configuration, with Temporal-based workflows coordinating provider APIs, ticketing actions, notifications, and auditable evidence handling through a provider-agnostic connector layer.

## 2. Architecture

The platform is organized into five connected layers: API Gateway and Lambda Authorizer validate ingress requests and enforce tenant identity, ingress services normalize provider payloads and route workflow starts, Temporal Workers execute deterministic workflows and activities, the Connector Adapter Layer abstracts provider-specific integrations behind stable actions, and AWS infrastructure services provide tenant configuration and persistence (SSM Parameter Store, S3, DynamoDB, EC2).

```text
Incoming Webhook
      |
      v
[Layer 1] API Gateway + Lambda Authorizer
      |
      v
[Layer 2] Ingress Services (Lambda/FastAPI normalize + route)
      |
      v
[Layer 3] Temporal Worker (workflow execution)
      |
      v
[Layer 4] Connector Adapter Layer (provider action)
      |
      v
[Layer 5] AWS Infrastructure (SSM/S3/DynamoDB/EC2)
      |
      v
Completed Workflow Action (ticket, notification, audit, containment)
```

`temporal-test` deployment topology:

```text
                        Internet
                           |
                           v
          +-------------------------------+
          | API Gateway (REST Ingress)   |
          | /api/v1/ingress/*            |
          +---------------+---------------+
                              |
                              v
          +-------------------------------+
          | Lambda Authorizer            |
          | tenant identity + auth check |
          +---------------+---------------+
                              |
                              v
          +-------------------------------+
          | Lambda Proxy (VPC-attached)  |
          | normalize + route workflow    |
          +---------------+---------------+
                              |
                        gRPC :7233
                              |
       +------------------v------------------+
       | VPC 10.99.0.0/16 (temporal-test)    |
       |                                      |
       |  Public Subnet                       |
       |  +--------------------------------+  |
       |  | EC2 secamo-temporal-test      |  |
       |  | Docker Compose stack:         |  |
       |  | - Temporal Server             |  |
       |  | - Temporal UI (:8080)         |  |
       |  | - PostgreSQL                  |  |
      |  | - secamo-worker               |  |
      |  | - secamo-graph-ingress        |  |
       |  +---------------+----------------+  |
       +------------------|-------------------+
                              |
      +-------------------+-----------------------------+
      | AWS Service Integrations                        |
      | - SSM Parameter Store (tenant config/secrets)   |
      | - S3 (evidence bundles)                         |
      | - DynamoDB (audit logs)                         |
      +-------------------------------------------------+
```

## 3. Supported Workflows

| ID    | Name                      | Trigger                                                                        | Description                                                                                                                                                         |
| ----- | ------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WF-01 | IAM Onboarding            | IAM ingress request (`/api/v1/ingress/iam`)                                    | Executes user lifecycle actions (`create`, `update`, `delete`, `password_reset`) using tenant-scoped Graph credentials, then writes audit records.                  |
| WF-02 | Defender Alert Enrichment | Security alert ingress (`/api/v1/ingress/defender` or `/api/v1/ingress/event`) | Enriches alert context, optionally runs threat intel fanout, computes risk score, creates/updates ticketing artifacts, sends notifications, and audits the outcome. |
| WF-05 | Impossible Travel HITL    | Impossible travel event ingress (`/api/v1/ingress/event`)                      | Creates triage ticket, sends human approval request, applies analyst decision or timeout policy (escalation/isolation), and optionally collects evidence bundle.    |

Additional orchestrators and child workflows used by the worker:

- WF-06 Graph Ingress Router handles `/graph/notifications` and starts routed SOC child workflows.
- WF-07 Graph Subscription Manager reconciles per-tenant Graph subscription lifecycle state via continue-as-new.
- PollingManagerWorkflow on `poller` queue for provider polling loops.
- Child SOC workflows: `AlertEnrichmentWorkflow`, `ThreatIntelEnrichmentWorkflow`, `TicketCreationWorkflow`, `HiTLApprovalWorkflow`, `IncidentResponseWorkflow`.
- Child IAM workflow: `UserDeprovisioningWorkflow`.
- ChatOps callback endpoint `/chatops/action` mounted in the Graph ingress service, signaling running workflows.

## 4. Supported Connectors

| Provider           | Type                    | Status     |
| ------------------ | ----------------------- | ---------- |
| Microsoft Defender | EDR / Alerting          | Production |
| Microsoft Graph    | Identity / Security API | Production |
| Jira               | Ticketing               | Production |
| HaloITSM           | Ticketing               | Stub       |
| ServiceNow         | Ticketing               | Stub       |
| CrowdStrike        | EDR                     | Stub       |
| SentinelOne        | EDR                     | Stub       |
| VirusTotal         | Threat Intel            | Stub       |
| AbuseIPDB          | Threat Intel            | Stub       |
| MISP               | Threat Intel Sharing    | Stub       |
| Microsoft Teams    | Notification            | Production |

ChatOps providers (used by `shared/providers/chatops` and webhook callbacks):

- Microsoft Teams
- Slack

AI triage provider support (used by `activities/triage.py`):

- Azure OpenAI (implemented)
- AWS Bedrock (planned)
- Local provider (planned)

For connector implementation and extension details, see `connectors/README.md`.

## 5. Repository Structure

```text
secamo-poc/
|-- activities/                 # Temporal activities (Graph, ticketing, notifications, audit, tenant config)
|   |-- graph_users.py          # IAM-related Graph operations
|   |-- graph_alerts.py         # Alert enrichment, alert lookup, containment, risk inputs
|   |-- graph_subscriptions.py  # Graph /subscriptions lifecycle + metadata persistence
|   |-- triage.py               # AI triage decision support activity
|   |-- chatops.py              # Interactive ChatOps notification activity
|   |-- connector_dispatch.py   # Provider-agnostic connector dispatch activities
|   |-- tenant.py               # Tenant validation, config retrieval, secret retrieval
|   `-- audit.py                # Audit log persistence and evidence bundle handling
|-- graph_ingress/              # FastAPI service for Graph validation + webhook ingress
|   |-- app.py                  # /graph/notifications endpoints
|   |-- chatops_webhook.py      # /chatops/action callback endpoint
|   |-- launcher.py             # Process launcher entrypoint for ingress container
|   |-- validator.py            # tenant resolution + clientState checks
|   `-- dispatcher.py           # Temporal workflow dispatch bridge
|-- connectors/                 # Connector adapter contract + provider implementations
|   |-- base.py                 # Abstract connector interface
|   |-- registry.py             # Provider registration and lookup
|   |-- microsoft_defender.py   # Defender connector implementation
|   |-- jira.py                 # Jira connector implementation
|   `-- stub_providers.py       # Stub connectors for planned providers
|-- shared/                     # Shared configuration, models, and helpers
|   |-- config.py               # Worker runtime settings and queue names
|   |-- graph_client.py         # Cached Graph/Defender token helper
|   |-- providers/              # AI + ChatOps provider abstractions and factories
|   |-- workflow_helpers.py     # Shared workflow bootstrap helper
|   `-- models/                 # Pydantic contracts for workflows, commands, ingress, canonical events
|-- workflows/                  # Temporal workflow definitions
|   |-- iam_onboarding.py       # WF-01
|   |-- defender_alert_enrichment.py  # WF-02
|   |-- graph_ingress_router.py # WF-06
|   |-- graph_subscription_manager.py # WF-07
|   `-- impossible_travel.py    # WF-05
|-- workers/                    # Worker bootstrap and queue registration
|   `-- run_worker.py           # Starts workers for iam-graph, soc-defender, audit, poller queues
|-- terraform/                  # Infrastructure as Code for AWS deployment
|   |-- environments/           # Environment-specific root modules
|   `-- modules/                # Reusable VPC, ingress, compute, storage, security modules
|-- tests/                      # Unit tests for models, activities, ingress mappers, token cache
`-- requirements.txt            # Python dependencies
```

## 6. Deploying the Test Environment

For complete infrastructure details, use `terraform/environments/temporal-test`.

1. Provision tenant parameters in SSM using these conventions:
   - Config path: `/secamo/tenants/{tenant_id}/config/{key}`
   - Secret path: `/secamo/tenants/{tenant_id}/{secret_type}/{key}`
2. Deploy infrastructure:
   - `cd terraform/environments/temporal-test`
   - `terraform init`
   - `terraform plan -var="my_ip=<YOUR_PUBLIC_IP>/32"`
   - `terraform apply -var="my_ip=<YOUR_PUBLIC_IP>/32"`
3. Start the worker process from repository root:
   - `python -m workers.run_worker`
4. Start the Graph ingress service:
      - `python -m graph_ingress.launcher`
5. Or start both as containers in the Temporal compose stack:
      - `docker compose -f terraform/temporal-compose/docker-compose.yml up -d secamo-worker secamo-graph-ingress`

## 7. Onboarding a New Tenant

1. Create an Entra ID app registration in the client tenant for Secamo automation.
2. Grant required Microsoft Graph and Defender API permissions, then provide admin consent in the client tenant.
3. Provision tenant configuration and secrets in SSM:
   - `/secamo/tenants/{tenant_id}/config/*`
   - `/secamo/tenants/{tenant_id}/graph/*`
   - `/secamo/tenants/{tenant_id}/ticketing/*`
   - `/secamo/tenants/{tenant_id}/threatintel/*`
   - `/secamo/tenants/{tenant_id}/chatops/*`
   - `/secamo/tenants/{tenant_id}/ai_triage/*`
4. Optional multi-tenant Graph subscription persistence:
   - Configure `GRAPH_SUBSCRIPTIONS_TABLE` for direct `subscription_id -> tenant_id` lookup.
   - Configure `TENANT_TABLE_NAME` to enable dynamic tenant registry activity.
5. Validate ingress and routing with test requests:
   - Provider ingress: `/api/v1/ingress/event`
   - Graph ingress challenge: `/graph/notifications?validationToken=...`
   - ChatOps callback: `/chatops/action`
6. Example provider ingress call:
   - `curl -X POST "https://<api-id>.execute-api.<region>.amazonaws.com/v1/api/v1/ingress/event" -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"provider":"microsoft_defender","event_type":"alert","id":"a-1","severity":"high","title":"test"}'`

## 8. Adding a New Connector

1. Implement a provider connector class under `connectors/` following the base contract.
2. Register the provider key in `connectors/registry.py`.
3. Update tenant configuration values and routing mappings as needed.
4. Add or update dispatch and normalizer coverage for ingress-triggered flows.
5. Add tests for connector behavior and workflow activity integration.

Full connector extension guidance is documented in `connectors/README.md`.

## 9. Environment Variables

- `TEMPORAL_ADDRESS` (required): Temporal gRPC endpoint used by workers and ingress dispatcher (for example `temporal:7233`).
- `TEMPORAL_NAMESPACE` (required): Temporal namespace for workflow execution.
- `AWS_REGION` (required): AWS region used by boto clients for SSM/S3/DynamoDB access.
- `EVIDENCE_BUCKET_NAME` (optional): S3 bucket used by evidence collection activities.
- `AUDIT_TABLE_NAME` (optional): DynamoDB table used by audit log activity.
- `SECAMO_SENDER_EMAIL` (optional): Sender identity for outbound email notifications.
- `GRAPH_SUBSCRIPTIONS_TABLE` (optional): DynamoDB table for Graph subscription metadata lookup by `subscription_id`.
- `TENANT_TABLE_NAME` (optional): DynamoDB table for dynamic active tenant discovery.
- `GRAPH_INGRESS_HOST` (optional): Bind host for ingress launcher, default `0.0.0.0`.
- `GRAPH_INGRESS_PORT` (optional): Bind port for ingress launcher, default `8081`.
