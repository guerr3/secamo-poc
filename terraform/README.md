# Terraform

> This folder provisions AWS infrastructure and bootstrap scripts for both the modular PoC environment and the single-node temporal-test environment.

## Files

| File | Purpose | Used By |
|------|---------|---------|
| `.gitignore` | Ignores Terraform local state/cache artifacts. | Local Terraform workflows. |
| `GUIDE.md` | Legacy long-form Terraform guide for this repository. | Human operators. |
| `walkthrough.md` | Legacy architecture/cost walkthrough for PoC deployment. | Human operators. |
| `encryption.json` | JSON policy snippet for S3 KMS encryption settings. | Storage hardening references. |
| `public-access.json` | JSON policy snippet for S3 public access block settings. | Storage hardening references. |
| `environments/poc/backend.tf` | Remote state backend config (S3 + DynamoDB lock). | `terraform init` in PoC environment. |
| `environments/poc/providers.tf` | AWS/random provider and version constraints for PoC. | PoC Terraform plan/apply. |
| `environments/poc/variables.tf` | Inputs for PoC deployment (region, VPC, sizes, tags, bucket naming). | PoC module composition. |
| `environments/poc/main.tf` | Root composition of `vpc`, `security`, `database`, `compute`, `ingress`, `storage` modules. | PoC environment provisioning. |
| `environments/poc/outputs.tf` | Exposes key PoC infra outputs (subnets, API endpoint, worker, DB, storage). | Post-deploy operations. |
| `environments/temporal-test/backend.tf` | Remote state backend config for temporal-test environment. | `terraform init` in temporal-test environment. |
| `environments/temporal-test/providers.tf` | AWS provider constraints for temporal-test. | Temporal-test plan/apply. |
| `environments/temporal-test/variables.tf` | Inputs for temporal-test (my_ip, instance size, keypair, namespace, repo URL). | Temporal-test provisioning. |
| `environments/temporal-test/main.tf` | Inline temporal-test stack (VPC/network/SG/IAM/EC2/bootstrap wiring). | Temporal-test provisioning. |
| `environments/temporal-test/outputs.tf` | Temporal-test outputs (public IP, UI URL, gRPC endpoint, commands). | Post-deploy operations. |
| `environments/temporal-test/ssm-policy.json` | IAM policy document for Session Manager operations. | Temporal-test IAM role policy. |
| `environments/temporal-test/walkthrough.md` | Legacy temporal-test deployment walkthrough. | Human operators. |
| `modules/vpc/main.tf` | VPC, subnets, IGW, route tables, and fck-nat instance resources. | PoC root module call. |
| `modules/vpc/variables.tf` | Input schema for VPC module. | PoC root module call. |
| `modules/vpc/outputs.tf` | VPC identifiers/subnets/NAT output values. | Downstream modules. |
| `modules/security/main.tf` | IAM roles/policies, security groups, and SSM parameter scaffolding for runtime secrets/config. | PoC root module call. |
| `modules/security/variables.tf` | Input schema for security module. | PoC root module call. |
| `modules/security/outputs.tf` | Security group IDs, role ARNs, and instance profile outputs. | Compute/ingress/database module wiring. |
| `modules/database/main.tf` | RDS PostgreSQL resources and subnet group. | PoC root module call. |
| `modules/database/variables.tf` | Input schema for database module. | PoC root module call. |
| `modules/database/outputs.tf` | Database endpoint/name/port outputs. | Compute bootstrap and outputs. |
| `modules/compute/main.tf` | Worker EC2 instance with IAM profile, SG, encrypted EBS, and startup script templating. | PoC root module call. |
| `modules/compute/variables.tf` | Input schema for compute module. | PoC root module call. |
| `modules/compute/outputs.tf` | Worker instance ID/private IP outputs. | PoC outputs. |
| `modules/ingress/main.tf` | API Gateway, Lambda authorizer/proxy packaging, permissions, routes, and stage logging. | PoC root module call. |
| `modules/ingress/variables.tf` | Input schema for ingress module (memory/timeout, subnet/SG, Temporal config, CIDRs). | PoC root module call. |
| `modules/ingress/outputs.tf` | API invoke URL, endpoint helpers, and Lambda identifiers. | PoC outputs and operations. |
| `modules/storage/main.tf` | Evidence S3 bucket + audit DynamoDB table provisioning with encryption and PITR. | PoC root module call. |
| `modules/storage/variables.tf` | Input schema for storage module. | PoC root module call. |
| `modules/storage/outputs.tf` | Bucket/table names and ARNs. | Security and root outputs. |
| `modules/ingress/src/authorizer/handler.py` | Lambda authorizer logic and cache/log env var usage. | API Gateway custom authorizer runtime. |
| `modules/ingress/src/ingress/handler.py` | Lambda ingress proxy logic and HITL token handling env var usage. | API Gateway proxy runtime. |
| `modules/ingress/src/ingress/mappers.py` | Provider payload normalization used by ingress lambda. | Ingress lambda and tests. |
| `scripts/temporal-startup.sh` | EC2 bootstrap script for temporal-test Docker Compose stack (Temporal + worker + ingress). | Temporal-test instance user-data. |
| `scripts/worker-startup.sh` | `[STUB]` PoC worker bootstrap script with commented container run/pull section pending CI/CD enablement. | PoC compute instance user-data. |
| `temporal-compose/docker-compose.yml` | Local/reference compose stack for Temporal server, UI, worker, and ingress. | Local development and temporal-test script source. |
| `temporal-compose/.env` | Version pins used by compose services. | Compose stack startup. |
| `temporal-compose/dynamicconfig/development-sql.yaml` | Temporal dynamic config for local SQL-backed deployment. | Temporal server startup. |
| `temporal-compose/scripts/setup-postgres.sh` | Creates Temporal and visibility DB/schema objects in Postgres. | Compose admin-tools init container. |
| `temporal-compose/scripts/create-namespace.sh` | Waits for Temporal availability and creates/describes namespace. | Compose namespace init container. |

## How It Fits

Infrastructure defined here provides the execution environment consumed by code in [../workers/README.md](../workers/README.md), [../graph_ingress/README.md](../graph_ingress/README.md), and [../activities/README.md](../activities/README.md). The PoC environment uses reusable modules for network/security/compute/database/storage/ingress, while temporal-test is a compact single-instance deployment for fast validation. Runtime code expects SSM, DynamoDB, and S3 resources created by these templates.

## Notes / Extension Points

- `scripts/worker-startup.sh` still has the worker container launch section commented out, so PoC bootstrap is not fully automated yet.
- Security module SSM parameters are scaffolded with placeholder values and intended to be overwritten through secure operational workflows.
- Ingress route/policy changes should stay aligned with runtime handlers in `modules/ingress/src`, normalization boundaries in `shared/normalization/normalizers.py`, and route mappings in `shared/routing/defaults.py`.
