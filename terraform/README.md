# Terraform

Infrastructure-as-code for ingress, runtime, storage, and environment-specific deployment topologies.

## Environment Inventory

| Environment                  | Purpose                                                     |
| ---------------------------- | ----------------------------------------------------------- |
| `environments/poc`           | Main modular PoC environment                                |
| `environments/temporal-test` | Single EC2 Temporal stack validation environment            |
| `environments/demo_tenant`   | Tenant-scoped demo footprint (AWS SSM + Azure VM resources) |
| `environments/demo_vm_aws`   | Standalone AWS Windows VM demo environment                  |

## Module Scope

- `modules/ingress`: API Gateway + proxy/authorizer Lambdas, including Graph notification routes and HiTL callback routes.
- `modules/storage`: evidence/audit storage resources.
- `temporal-compose/`: local/self-hosted Temporal startup artifacts.
- `scripts/`: bootstrap scripts for host/runtime setup.

## Runtime Notes (Current Behavior)

- Ingress Terraform defines both POST and GET methods for Graph notifications route (`/api/v1/graph/notifications/{tenant_id}`), where GET supports Graph validation token exchange.
- Ingress Terraform includes HiTL callback routes (`/api/v1/hitl/respond` and `/api/v1/hitl/jira/{tenant_id}`).
- Temporal namespace bootstrap script auto-creates required custom search attributes (`TenantId`, `CaseType`, `Severity`, `HiTLStatus`) idempotently.
- Temporal-test environment IAM policy now includes access to HiTL token table for worker/runtime operations.

## Usage

```bash
cd terraform/environments/<environment>
terraform init
terraform fmt -check
terraform validate
terraform plan
terraform apply
```

## Verification

Infrastructure guardrail tests:

```bash
python -m pytest -q tests/test_ingress_terraform_graph_validation_route.py
```

## Change Checklist

1. Keep environment variables aligned with runtime code expectations.
2. Keep ingress routes and handler mappings aligned.
3. Keep IAM permissions aligned with activity/runtime storage access patterns.
4. Validate with `terraform fmt -check` and `terraform validate` before apply.
5. Update environment-specific README files when behavior changes.
