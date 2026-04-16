# Terraform Walkthrough

This document explains how to work with Terraform in this repository without relying on point-in-time generation snapshots.

## Scope

The Terraform layout currently supports:

- `environments/poc` for the modular PoC stack.
- `environments/temporal-test` for a single-node Temporal validation environment.
- `environments/demo_tenant` for tenant-scoped demo provisioning (AWS + Azure).
- `environments/demo_vm_aws` for standalone AWS Windows VM demo/testing.
- `modules/*` for reusable network, security, compute, ingress, storage, and database components.
- `scripts/*` for instance bootstrap logic.

See [README.md](README.md) for the canonical inventory and file-level map.

## Expected Workflow

Run Terraform from an environment folder, not from `terraform/` root.

```bash
cd terraform/environments/<environment>
terraform init
terraform plan
terraform apply
```

Examples:

```bash
# main PoC environment
cd terraform/environments/poc

# self-hosted Temporal validation environment
cd terraform/environments/temporal-test

# tenant demo footprint
cd terraform/environments/demo_tenant

# standalone AWS demo VM
cd terraform/environments/demo_vm_aws
```

## Prerequisites

Before `terraform init`, ensure:

1. AWS credentials are valid for the target account.
2. The backend S3 bucket exists and has versioning/encryption.
3. The DynamoDB lock table exists.
4. Backend settings in environment `backend.tf` match your account resources.

## Validation Commands

Use these commands any time Terraform code changes:

```bash
terraform fmt -check
terraform validate
```

If you want to validate without remote backend access:

```bash
terraform init -backend=false
terraform validate
```

## Notes

- Avoid hardcoding account IDs or local absolute paths in shared docs.
- Treat cost examples as illustrative only; verify with current AWS pricing and actual instance selections in code.
- Keep this walkthrough aligned with [terraform/README.md](README.md), [terraform/GUIDE.md](GUIDE.md), and environment-specific docs.
