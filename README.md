# Secamo Process Orchestrator (PoC)

Multi-tenant security automation platform built on [Temporal](https://temporal.io/) — orchestrating IAM lifecycle management, SOC alert enrichment, and impossible travel detection via Microsoft Graph API.

## Architecture Overview

All components run as Docker containers on a **single EC2 instance** (t3.medium) provisioned via Terraform.

```text
┌──────────────────────── AWS Cloud ───────────────────────────────────┐
│                                                                    │
│  [ Webhooks / Clients ]                                            │
│           │ POST /api/v1/ingress/...                               │
│  ┌────────▼───────┐                                                │
│  │ API Gateway    │◄──── (Resource Policy IP Allowlist)            │
│  │ (REST API)     │                                                │
│  └──────┬─┬───────┘                                                │
│         │ └─────────────────────────┐                              │
│  ┌──────▼───────┐   ┌───────────────▼─────────┐                    │
│  │ Authorizer   │   │ Proxy Lambda (VPC)      │◄── Lambda Layer    │
│  │ Lambda       │   │ ingress_sdk routing     │    (temporalio)    │
│  └──────────────┘   └───────────────┬─────────┘                    │
│                                     │ gRPC :7233                   │
│ ┌───────────────────────────────────▼────────────────────────────┐ │
│ │                  EC2 Instance (t3.medium)                      │ │
│ │  Docker Compose Network: temporal-network                      │ │
│ │  ┌──────────────┐  ┌───────────────────────┐  ┌───────────────┐│ │
│ │  │ PostgreSQL   │  │ Temporal Server 1.29.1│  │ Temporal UI   ││ │
│ │  │ :5432        │◄─│ gRPC :7233            │  │ :8080         ││ │
│ │  └──────────────┘  └───────────┬───────────┘  └───────────────┘│ │
│ │                                │                               │ │
│ │                    ┌───────────▼────────────┐                  │ │
│ │                    │ secamo-worker          │                  │ │
│ │                    │ Python 3.11            │                  │ │
│ │                    │ ┌─────────┐ ┌────────┐ │                  │ │
│ │                    │ │ Activit.│ │Workfl. │ │                  │ │
│ │                    │ │ Graph   │ │IAM     │ │                  │ │
│ │                    │ │ SOC     │ │Defender│ │                  │ │
│ │                    │ │ Audit   │ │Travel  │ │                  │ │
│ │                    │ └─────────┘ └────────┘ │                  │ │
│ │                    └────────────────────────┘                  │ │
│ └────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Temporal Server** = orchestration brain (state, retries, task queues) — never touches your code
- **Workers** = your Python code running activities and workflows — poll Temporal for tasks
- **Secrets** stay on the worker side (Graph API credentials never reach Temporal Server)

## Front Door Ingress (API Gateway & Lambdas)

To securely receive external webhooks (e.g., from Microsoft Defender or Teams) and translate them into Temporal workflows, Secamo uses a serverless Front Door architecture:

1. **API Gateway (REST API)**: The entry point for all external traffic. It uses a **Resource Policy** to enforce infrastructure-level IP allowlisting (restricting access to Microsoft IP ranges).
2. **Authorizer Lambda**: A custom Lambda Authorizer that inspects incoming requests, validates tenant identity, and injects a `tenant_id` into the request context to achieve multi-tenancy.
3. **Proxy Lambda (VPC)**: Placed inside private subnets within the VPC to communicate directly with the Temporal EC2 instance via gRPC (port 7233). It parses the webhook and uses the Temporal SDK to start or signal workflows.
4. **Lambda Layer (`secamo-ingress-layer`)**: To keep the Proxy Lambda entirely DRY, all Temporal connection logic, API event parsing, response formatting, and async dispatching is extracted into a shared `ingress_sdk` Lambda Layer. The proxy handler contains only pure business logic (~20 lines per route).

### Webhook Flow
When a webhook arrives at `POST /api/v1/ingress/defender`:
1. API Gateway validates the source IP against the Resource Policy.
2. The Authorizer Lambda validates the payload/token and returns an IAM Allow policy + `tenant_id`.
3. The Proxy Lambda receives the event, parses it using `ingress_sdk`, and connects to the Temporal Server.
4. The Proxy Lambda starts the `DefenderAlertEnrichmentWorkflow` on the `soc-defender` task queue.
5. API Gateway immediately returns an HTTP 202 Accepted with the `workflow_id`, while the EC2 workers pick up and execute the workflow asynchronously.

## Project Structure

```
secamo-poc/
├── Dockerfile                  # Multi-stage Python 3.11-slim worker image
├── requirements.txt            # Python dependencies
├── .env.example                # Template for worker environment variables
│
├── shared/                     # Shared modules
│   ├── config.py               # Environment-based configuration loader
│   └── models.py               # Dataclasses for all workflow I/O
│
├── activities/                 # Temporal activities (business logic)
│   ├── graph_users.py          # Microsoft Graph user CRUD via msgraph-sdk
│   ├── graph_alerts.py         # Defender alert enrichment & threat intel
│   ├── tenant.py               # Tenant validation & secret retrieval
│   ├── ticketing.py            # Ticket create/update/close
│   ├── notifications.py        # Teams & email notifications
│   └── audit.py                # Audit logging & evidence collection
│
├── workflows/                  # Temporal workflow definitions
│   ├── iam_onboarding.py       # WF-01: User lifecycle (create/update/delete/reset)
│   ├── defender_alert_enrichment.py  # WF-02: SOC alert triage & ticketing
│   └── impossible_travel.py    # WF-05: HITL impossible travel detection
│
├── workers/
│   └── run_worker.py           # Worker entrypoint — starts 3 task queue workers
│
└── terraform/
    ├── environments/
    │   └── temporal-test/      # Standalone Temporal EC2 environment
    │       ├── main.tf         # VPC, SG, IAM, EC2 (all inline)
    │       ├── variables.tf    # Inputs: my_ip, Graph creds, GitHub URL
    │       ├── outputs.tf      # Public IP, UI URL, gRPC endpoint
    │       ├── providers.tf    # AWS eu-west-1
    │       └── backend.tf      # S3 remote state
    ├── scripts/
    │   └── temporal-startup.sh # EC2 user-data: Docker install, git clone, compose up
    └── temporal-compose/       # Reference docker-compose files (used by startup.sh)
        ├── docker-compose.yml
        ├── .env                # Container image version pins
        ├── dynamicconfig/
        └── scripts/            # DB schema init + namespace creation
```

## Workflows

### WF-01 — IAM Onboarding (User Lifecycle)

| | |
|---|---|
| **Task Queue** | `iam-graph` |
| **Input** | `LifecycleRequest` (tenant, action, user_data, requester, ticket_id) |
| **Actions** | `create` · `update` · `delete` · `password_reset` |
| **Activities** | validate_tenant → get_secrets → graph_get_user → action-specific Graph API call → audit_log |

```
create:  validate → get_secrets → check_exists → graph_create_user → [assign_license] → audit
update:  validate → get_secrets → check_exists → graph_update_user → audit
delete:  validate → get_secrets → check_exists → revoke_sessions → graph_delete_user → audit
reset:   validate → get_secrets → check_exists → graph_reset_password → audit
```

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
| **Timeout** | 4 hours for human approval, then auto-escalates |

## Docker Configuration

### Dockerfile

Multi-stage build for a minimal worker image (~180 MB):

```dockerfile
# Stage 1: Install Python dependencies
FROM python:3.11-slim AS builder
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Copy app code, run as non-root
FROM python:3.11-slim
COPY --from=builder /install /usr/local
COPY shared/ activities/ workflows/ workers/ ./
USER worker
ENTRYPOINT ["python", "-m", "workers.run_worker"]
```

### Docker Compose Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `postgresql` | `postgres:16` | 5432 | Temporal persistence + visibility store |
| `temporal` | `temporalio/server:1.29.1` | 7233 | Workflow orchestration (gRPC) |
| `temporal-ui` | `temporalio/ui:2.34.0` | 8080 | Web dashboard |
| `temporal-admin-tools` | `temporalio/admin-tools` | — | Schema setup (runs once) |
| `temporal-create-namespace` | `temporalio/admin-tools` | — | Creates `default` namespace (runs once) |
| `secamo-worker` | Built from `Dockerfile` | — | Python worker (activities + workflows) |

The worker connects to Temporal via Docker's internal DNS: `TEMPORAL_ADDRESS=temporal:7233`.

## Terraform Infrastructure

### Resources (defined inline in `main.tf`)

| Resource | Configuration |
|----------|---------------|
| **VPC** | `10.99.0.0/16`, 1 public subnet, Internet Gateway |
| **Security Group** | Inbound 22/7233/8080 restricted to `var.my_ip` only |
| **IAM** | Instance profile with SSM access (`AmazonSSMManagedInstanceCore`) |
| **EC2** | t3.medium, Amazon Linux 2023, 30 GB gp3 encrypted EBS |

### Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `my_ip` | ✅ | Your public IP in CIDR notation (e.g. `1.2.3.4/32`) |
| `github_repo_url` | — | Repo URL for git clone (default: `guerr3/secamo-poc`) |
| `graph_tenant1_id` | — | Microsoft Graph tenant ID |
| `graph_client1_id` | — | Microsoft Graph client (app) ID |
| `graph_secret1_value` | — | Microsoft Graph client secret |
| `graph_secret1_id` | — | Microsoft Graph secret ID |
| `instance_type` | — | EC2 type (default: `t3.medium`) |
| `volume_size` | — | EBS size in GB (default: `30`) |

### EC2 Bootstrap Flow (`temporal-startup.sh`)

```
[1/6] Install Docker, Docker Compose, Git
[2/6] Write docker-compose.yml, scripts, dynamicconfig inline
[3/6] Git clone secamo-poc repo + write worker .env
[4/6] Start Temporal infrastructure containers
[5/6] Wait for Temporal server health check
[6/6] Build worker Docker image + start secamo-worker container
```

## Deployment

### Prerequisites

- AWS CLI configured with credentials
- Terraform ≥ 1.6
- Temporal CLI (optional, for starting workflows)

### Deploy

```bash
cd terraform/environments/temporal-test

terraform init

terraform apply \
  -var="my_ip=$(curl -s ifconfig.me)/32" \
  -var="graph_tenant1_id=YOUR_TENANT_ID" \
  -var="graph_client1_id=YOUR_CLIENT_ID" \
  -var="graph_secret1_value=YOUR_SECRET" \
  -var="graph_secret1_id=YOUR_SECRET_ID"
```

After ~5 minutes, Terraform outputs:

```
temporal_ui_url          = "http://<ip>:8080"
temporal_grpc_endpoint   = "<ip>:7233"
ssh_command              = "Use SSM: aws ssm start-session --target <id>"
```

### Verify

```bash
# SSM into the EC2
aws ssm start-session --target <instance_id> --region eu-west-1

# Check all containers are running
sudo docker ps
# Expected: temporal-postgresql, temporal, temporal-ui, secamo-worker

# Check worker logs
sudo docker logs -f secamo-worker
```

### Destroy

```bash
terraform destroy -var="my_ip=$(curl -s ifconfig.me)/32"
```

## Starting Workflows

### Via Temporal CLI

```bash
temporal workflow start \
  --address <EC2_IP>:7233 \
  --namespace default \
  --task-queue iam-graph \
  --type IamOnboardingWorkflow \
  --workflow-id my-workflow-001 \
  --input '{
    "tenant_id": "tenant-demo-001",
    "action": "create",
    "user_data": {
      "email": "john.doe@contoso.com",
      "first_name": "John",
      "last_name": "Doe",
      "department": "IT Security",
      "role": "SOC Analyst",
      "manager_email": null,
      "license_sku": null
    },
    "requester": "admin@contoso.com",
    "ticket_id": "TKT-001"
  }'
```

### Via Python SDK

```python
from temporalio.client import Client

client = await Client.connect("<EC2_IP>:7233", namespace="default")

handle = await client.start_workflow(
    "IamOnboardingWorkflow",
    {"tenant_id": "t1", "action": "create", "user_data": {...}, ...},
    id="my-workflow-001",
    task_queue="iam-graph",
)

result = await handle.result()
```

### Monitoring

Open the **Temporal UI** at `http://<EC2_IP>:8080` to:
- View running and completed workflows
- Inspect event history and activity results
- Search workflows by ID, type, or status
- View worker task queue pollers

## Environment Variables

The worker requires these environment variables (injected via `.env` on the EC2):

| Variable | Purpose |
|----------|---------|
| `TEMPORAL_ADDRESS` | Temporal gRPC endpoint (`temporal:7233` on EC2, `<ip>:7233` locally) |
| `TEMPORAL_NAMESPACE` | Temporal namespace (default: `default`) |
| `TEMPORAL_API_KEY` | Only for Temporal Cloud (leave empty for self-hosted) |
| `GRAPH_TENANT1_ID` | Azure AD tenant ID |
| `GRAPH_CLIENT1_ID` | App registration client ID |
| `GRAPH_SECRET1_VALUE` | App registration client secret |
| `GRAPH_SECRET1_ID` | Secret ID |

## Local Development

Run the worker locally against the EC2 Temporal server:

```bash
# Create .env from template
cp .env.example .env
# Edit .env: set TEMPORAL_ADDRESS=<EC2_IP>:7233 + Graph credentials

# Install dependencies
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows
pip install -r requirements.txt

# Start worker
python -m workers.run_worker
```

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
| SDK | temporalio (Python SDK) |
| Identity Provider | Microsoft Graph API (msgraph-sdk) |
| Infrastructure | Terraform + AWS (EC2, VPC, IAM) |
| Containers | Docker Compose |
| UI | Temporal Web UI 2.34.0 |
