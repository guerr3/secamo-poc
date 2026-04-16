# Terraform - infrastructure definitions for ingress, runtime, and storage layers

> This module provisions infrastructure for multiple isolated runtime environments.

## Responsibilities

- Define reusable infrastructure modules for network, security, compute, ingress, storage, and database.
- Define environment entrypoints with isolated state and lifecycle.
- Provide bootstrap scripts and compose assets for local/self-hosted Temporal runtime.
- Keep runtime infrastructure aligned with ingress/worker/activity operational requirements.

## Environment Inventory

| Environment                  | Purpose                                                 |
| ---------------------------- | ------------------------------------------------------- |
| `environments/poc`           | Main modular AWS PoC environment.                       |
| `environments/temporal-test` | Single-node Temporal validation environment on EC2.     |
| `environments/demo_tenant`   | Tenant-scoped demo environment (AWS + Azure resources). |
| `environments/demo_vm_aws`   | Standalone AWS Windows VM demo/testing environment.     |

## File Reference

| File                 | Responsibility                                                      |
| -------------------- | ------------------------------------------------------------------- |
| `.gitignore`         | Ignore Terraform local state and cache artifacts.                   |
| `encryption.json`    | S3 encryption policy snippet reference.                             |
| `environments/`      | Environment-specific Terraform entrypoints and state configuration. |
| `GUIDE.md`           | Detailed Terraform operator guide.                                  |
| `modules/`           | Reusable Terraform modules.                                         |
| `public-access.json` | S3 public access block policy snippet reference.                    |
| `README.md`          | Module documentation.                                               |
| `scripts/`           | Bootstrap scripts for infrastructure hosts.                         |
| `temporal-compose/`  | Compose files and helper scripts for Temporal stack startup.        |
| `walkthrough.md`     | Terraform quick-start workflow guide.                               |

## Usage

Run Terraform from an environment directory:

```bash
cd terraform/environments/<environment>
terraform init
terraform plan
terraform apply
```

## Validation

```bash
cd terraform/environments/<environment>
terraform fmt -check
terraform validate
```

## Extension Points

1. Add or extend a module under `terraform/modules/` for new infrastructure capabilities.
2. Wire module inputs/outputs in the target environment entrypoint under `terraform/environments/`.
3. Keep IAM, networking, and runtime env vars aligned with code-level expectations.
4. Validate with `terraform fmt -check` and `terraform validate` before apply.
5. Update environment walkthrough docs when environment behavior changes.
