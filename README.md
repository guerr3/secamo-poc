# Secamo Process Orchestrator (PoC)

Multi-tenant security automation platform built on [Temporal](https://temporal.io/) — orchestrating IAM lifecycle management, SOC alert enrichment, and impossible travel detection via Microsoft Graph API.

## Architecture Overview

All components run as Docker containers on a **single EC2 instance** (t3.medium), protected by a Serverless **Front Door Ingress architecture**. Infrastructure is provisioned via Terraform.

```text
┌──────────────────────── AWS Cloud ───────────────────────────────────────────┐
│                                                                            │
│  [ Webhooks / Clients ]                                                    │
│           │ POST /api/v1/ingress/{defender, teams, iam}                    │
│  ┌────────▼───────┐                                                        │
│  │ API Gateway    │◄──── (Resource Policy IP Allowlist)                    │
│  │ (REST API)     │                                                        │
│  └──────┬─┬───────┘                                                        │
│         │ └─────────────────────────┐                                      │
│  ┌──────▼───────┐   ┌───────────────▼─────────┐                            │
│  │ Authorizer   │   │ Proxy Lambda (VPC)      │◄── Lambda Layer            │
│  │ Lambda       │   │ ingress_sdk routing     │    (temporalio)            │
│  └──────────────┘   └───────────────┬─────────┘                            │
│                                     │ gRPC :7233                           │
│ ┌───────────────────────────────────▼────────────────────────────────────┐ │
│ │                  EC2 Instance (t3.medium)                              │ │
│ │  Docker Compose Network: temporal-network                              │ │
│ │  ┌──────────────┐  ┌───────────────────────┐  ┌───────────────┐        │ │
│ │  │ PostgreSQL   │  │ Temporal Server 1.29.1│  │ Temporal UI   │        │ │
│ │  │ :5432        │◄─│ gRPC :7233            │  │ :8080         │        │ │
│ │  └──────────────┘  └───────────┬───────────┘  └───────────────┘        │ │
│ │                                │                                       │ │
│ │                    ┌───────────▼────────────┐  IAM Instance Profile    │ │
│ │                    │ secamo-worker          │  fetches secrets         │ │
│ │                    │ Python 3.11            ├────────────────┐         │ │
│ │                    │ ┌─────────┐ ┌────────┐ │                │         │ │
│ │                    │ │ Activit.│ │Workfl. │ │       ┌────────▼───────┐ │ │
│ │                    │ │ Graph   │ │IAM     │ │       │ AWS SSM        │ │ │
│ │                    │ │ SOC     │ │Defender│ │       │ Parameter Store│ │ │
│ │                    │ │ Audit   │ │Travel  │ │       └────────────────┘ │ │
│ │                    │ └─────────┘ └────────┘ │                          │ │
│ │                    └────────────────────────┘                          │ │
│ └────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Temporal Server** = orchestration brain (state, retries, task queues) — never touches your code.
- **Workers** = your Python code running activities and workflows — poll Temporal for tasks.
- **Secrets Management** = Local `.env` files are deprecated. Secrets (like Microsoft Graph credentials) never reach the Temporal Server. Workers proactively fetch them contextually per-tenant from **AWS SSM Parameter Store** via their EC2 IAM instance profile.
- **Strict Data Contracts** = All workflow Inputs and Outputs are strongly typed via Pydantic v2.

## Front Door Ingress (API Gateway & Lambdas)

To securely receive external webhooks (e.g., from Microsoft Defender, Teams, or our own internal services) and translate them into Temporal workflows, Secamo uses a serverless Front Door Architecture defined in the `ingress` Terraform module:

1. **API Gateway (REST API)**: The entry point for all external traffic. It exposes routes like `/api/v1/ingress/defender`, `/api/v1/ingress/teams`, and `/api/v1/ingress/iam`. It uses a **Resource Policy** to enforce infrastructure-level IP allowlisting (restricting access to Microsoft IP ranges).
2. **Authorizer Lambda**: A custom Lambda Authorizer that inspects incoming requests, validates the authentication tokens, and extracts a `tenant_id` which is injected into the request context to guarantee multi-tenancy.
3. **Proxy Lambda (VPC)**: Placed inside private subnets within the VPC to communicate directly with the Temporal EC2 instance via gRPC (port 7233). It parses the webhook into Pydantic events and uses the Temporal SDK to start or signal workflows.
4. **Lambda Layer (`secamo-ingress-layer`)**: To keep the Proxy Lambda entirely DRY, all Temporal connection logic, API event parsing, response formatting, and async dispatching is extracted into a shared `ingress_sdk` Lambda Layer. 

### End-to-End Functional Flow (Webhook to Execution)

1. **Client Request**: An external service (e.g., Defender) sends a webhook POST to API Gateway `POST /api/v1/ingress/defender`.
2. **Gateway Validation**: API Gateway checks if the source IP matches the Resource Policy allowlist.
3. **Authorization**: The Authorizer Lambda validates the payload signature/token and returns an IAM Allow policy + injected `tenant_id`.
4. **Proxy Hand-off**: The Proxy Lambda receives the authorized event, formats it using the shared Pydantic `RawIngressEnvelope` model from the Lambda Layer, and connects to the Temporal Server via gRPC.
5. **Workflow Kickoff**: The Proxy Lambda starts the `DefenderAlertEnrichmentWorkflow` on the `soc-defender` task queue.
6. **Asynchronous Response**: API Gateway immediately returns an HTTP 202 Accepted with the mapped `workflow_id`.
7. **Worker Execution**: The EC2 `secamo-worker` polls the `soc-defender` queue, picks up the task, dynamically fetches the Azure AD credentials for the specified `tenant_id` from AWS SSM Parameter store, and executes the business logic (Microsoft Graph lookups, ticketing, etc.).

## Unified Data Models (Pydantic)

The codebase has migrated from standard Python dataclasses to **Pydantic v2** to ensure rigorous, end-to-end data integrity. You can find all domain models inside the `shared/models/` directory:

- `domain.py`: The canonical workflow definitions, tracking all data associated with core business boundaries (e.g., `UserData`, `LifecycleRequest`, `AlertData`).
- `commands.py`: Activity inputs mapping exact instructions passed from Temporal workflows to the Python workers.
- `ingress.py`: Ingress transport models dealing with raw data envelopes (`RawIngressEnvelope`) entering the Proxy Lambda prior to workflow conversion.
- `provider_events.py`: Parsing schemas to standardise raw webhook payloads from external integrations (Microsoft Graph, Defender, Teams).

## Workflows

### WF-01 — IAM Onboarding (User Lifecycle)

| | |
|---|---|
| **Task Queue** | `iam-graph` |
| **Input** | `LifecycleRequest` (tenant, action, user_data, requester, ticket_id) |
| **Actions** | `create` · `update` · `delete` · `password_reset` |
| **Activities** | validate_tenant → get_secrets → graph_get_user → action-specific Graph API call → audit_log |

### WF-02 — Defender Alert Enrichment & Ticketing

| | |
|---|---|
| **Task Queue** | `soc-defender` |
| **Input** | `DefenderAlertRequest` (tenant, alert, requester) |
| **Activities** | validate → get_secrets → enrich_alert → threat_intel → risk_score → create_ticket → teams_notify → audit |

### WF-05 — Impossible Travel (Human-in-the-Loop)

| | |
|---|---|
| **Task Queue** | `soc-defender` |
| **Input** | `ImpossibleTravelRequest` (tenant, alert, user, IPs, requester) |
| **Signal** | `approve` — receives analyst decision (dismiss / isolate / disable) |

## Deployment (Terraform)

### Prerequisites

- AWS CLI configured with credentials
- Terraform ≥ 1.6
- Temporal CLI (optional, for manual interaction)

### Deploy Infrastructure

Because tenant secrets are now managed through AWS SSM Parameter Store, the initial deployment requires significantly fewer variables:

```bash
cd terraform/environments/temporal-test

terraform init

terraform apply \
  -var="my_ip=$(curl -s ifconfig.me)/32"
```

After ~5 minutes, Terraform outputs:

```
temporal_ui_url          = "http://<ip>:8080"
temporal_grpc_endpoint   = "<ip>:7233"
api_gateway_endpoint     = "https://<api_id>.execute-api.eu-west-1.amazonaws.com/v1"
ssh_command              = "Use SSM: aws ssm start-session --target <id>"
```

### Provisioning Secrets

After deployment, you must populate the AWS SSM Parameter Store with your tenant secrets. Run:

```bash
aws ssm put-parameter --name "/secamo/tenants/t1/graph/client_id" --value "YOUR_CLIENT_ID" --type SecureString
aws ssm put-parameter --name "/secamo/tenants/t1/graph/client_secret" --value "YOUR_SECRET" --type SecureString
aws ssm put-parameter --name "/secamo/tenants/t1/graph/tenant_azure_id" --value "YOUR_AZURE_TENANT_ID" --type SecureString
```

The worker EC2 instance profile automatically has decryption rights for the pattern `/secamo/tenants/*`.

### Destroy Infrastructure

```bash
terraform destroy -var="my_ip=$(curl -s ifconfig.me)/32"
```

## Demo & Manual Testing

You can use standard `curl` commands to hit the public API Gateway endpoints mimicking webhooks to test the entire stack. Don't forget to replace the `API_GATEWAY_URL` with your deployment URL.

### Testing IAM Workflow (WF-01)
```bash
curl -X POST "https://<API_GATEWAY_URL>/api/v1/ingress/iam" \
  -H "Authorization: Bearer <MOCK_VALID_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "create",
    "user_data": {
      "email": "test.user@contoso.com",
      "first_name": "Test",
      "last_name": "User",
      "department": "Engineering",
      "role": "Developer"
    },
    "requester": "admin@contoso.com",
    "ticket_id": "TKT-102"
  }'
```

### Testing Defender Webhook (WF-02)
```bash
curl -X POST "https://<API_GATEWAY_URL>/api/v1/ingress/defender" \
  -H "Authorization: Bearer <MOCK_VALID_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "alertId": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "severity": "High",
    "title": "Suspicious PowerShell Execution",
    "description": "Observed unusual process spawning from powershell.exe",
    "device": {"id": "device-1234"},
    "user": {"email": "test.user@contoso.com"}
  }'
```

_Note: If testing remotely, make sure your public IP is added to the `microsoft_allowed_cidrs` variable in Terraform, as API Gateway utilizes a restrictive Resource Policy by default._

## Monitoring

Open the **Temporal UI** at `http://<EC2_IP>:8080` to view workflows kicking off automatically in response to the webhooks.

## Task Queues

| Queue | Workflows | Description |
|-------|-----------|-------------|
| `iam-graph` | IamOnboardingWorkflow | IAM user lifecycle via Microsoft Graph |
| `soc-defender` | DefenderAlertEnrichmentWorkflow, ImpossibleTravelWorkflow | SOC automation & alert triage |
| `audit` | — | Audit-only activities (no workflows bound) |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Orchestration | Temporal Server 1.29.1 |
| Database | PostgreSQL 16 |
| Worker Runtime | Python 3.11 |
| Data Validation | Pydantic v2 |
| SDK | temporalio (Python SDK) |
| Secrets Management | AWS SSM Parameter Store |
| Identity Provider | Microsoft Graph API (msgraph-sdk) |
| Infrastructure | Terraform + AWS (API GW, EC2, VPC, IAM) |
| Containers | Docker Compose |
