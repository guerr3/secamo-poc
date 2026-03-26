# Terraform - infrastructure definitions for ingress, runtime, and storage layers

> This module provisions AWS infrastructure and deployment assets for PoC and temporal-test environments.

## Responsibilities

- Define reusable infrastructure modules for network, security, compute, ingress, storage, and database.
- Define environment entrypoints for PoC and temporal-test deployments.
- Provide bootstrap scripts and compose assets for local/test Temporal runtime.
- Keep runtime infrastructure aligned with ingress/worker/activity operational requirements.

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

## Key Concepts

- Module composition: environment roots wire reusable modules to keep infrastructure concerns separated.
- Environment isolation: `environments/poc` and `environments/temporal-test` use independent state and lifecycle control.
- Runtime coupling: ingress Lambda, worker hosts, and persistence stores are provisioned to match orchestration layer boundaries.

## Usage

Run Terraform from an environment directory.

```bash
cd terraform/environments/poc
terraform init
terraform plan
terraform apply
```

## Testing

```bash
cd terraform/environments/poc
terraform fmt -check
terraform validate
```

## Extension Points

1. Add or extend a module under `terraform/modules/` for new infrastructure capabilities.
2. Wire module inputs/outputs in the target environment entrypoint (`environments/poc` or `environments/temporal-test`).
3. Keep IAM, networking, and runtime env vars aligned with code-level expectations.
4. Validate with `terraform fmt -check` and `terraform validate`.
5. Update environment walkthrough docs and this file reference as needed.
