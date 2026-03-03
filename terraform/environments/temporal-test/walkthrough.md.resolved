# Walkthrough — Temporal Self-Hosted on Single EC2

## What Was Built

A standalone Terraform environment (`temporal-test`) that deploys a single EC2 instance running the full Temporal stack via docker-compose, **without touching the existing `poc` architecture**.

### Architecture

```
┌─────────────────────────────────────────────────┐
│  EC2 (t3.medium) — Amazon Linux 2023            │
│                                                 │
│  ┌──────────────┐  ┌────────────────────────┐   │
│  │ PostgreSQL   │  │ Temporal Server 1.29.1 │   │
│  │ v16          │←─│ gRPC :7233             │   │
│  └──────────────┘  └────────────────────────┘   │
│                    ┌────────────────────────┐   │
│                    │ Temporal UI 2.34.0     │   │
│                    │ HTTP :8080             │   │
│                    └────────────────────────┘   │
│  All containers on Docker bridge network        │
└─────────────────────────────────────────────────┘
          │ Public subnet, SG: your IP only
```

### Files Created

| Path | Description |
|------|-------------|
| [main.tf](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/environments/temporal-test/main.tf) | VPC, SG, IAM, EC2 — all inline |
| [variables.tf](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/environments/temporal-test/variables.tf) | `my_ip` (required), `instance_type`, `key_pair_name` |
| [outputs.tf](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/environments/temporal-test/outputs.tf) | Public IP, UI URL, gRPC endpoint, SSH/SSM cmd |
| [providers.tf](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/environments/temporal-test/providers.tf) | AWS provider in eu-west-1 |
| [backend.tf](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/environments/temporal-test/backend.tf) | S3 remote state (separate key) |
| [temporal-startup.sh](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/scripts/temporal-startup.sh) | EC2 user-data: installs Docker, writes compose files, starts stack |
| [docker-compose.yml](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/temporal-compose/docker-compose.yml) | PostgreSQL-only Temporal stack (reference copy) |
| [.env](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/temporal-compose/.env) | Image version pins |
| [setup-postgres.sh](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/temporal-compose/scripts/setup-postgres.sh) | DB schema initialization |
| [create-namespace.sh](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/temporal-compose/scripts/create-namespace.sh) | Namespace creation after health check |

## Verification

✅ `terraform init -backend=false` — passed  
✅ `terraform validate` — **Success! The configuration is valid.**

## Deploy Instructions

```bash
cd terraform/environments/temporal-test

# Initialize (with real backend)
terraform init

# Plan — pass your public IP
terraform plan -var="my_ip=$(curl -s ifconfig.me)/32"

# Apply
terraform apply -var="my_ip=$(curl -s ifconfig.me)/32"
```

After ~3-5 minutes the outputs show:
- **temporal_ui_url** → open in browser to see the Temporal Web UI
- **temporal_grpc_endpoint** → use as `--address` in Temporal CLI or SDK client connection

## Destroy

```bash
terraform destroy -var="my_ip=$(curl -s ifconfig.me)/32"
```
