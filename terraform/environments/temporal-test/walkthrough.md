# Walkthrough — Temporal Self-Hosted on Single EC2

This walkthrough is the operator guide for the `terraform/environments/temporal-test` environment.

## Purpose

`temporal-test` provisions a single EC2 host that runs a Docker Compose-based Temporal stack for quick validation and demos, isolated from the modular PoC environment.

## Key Files

| Path                                                                                                   | Description                                                               |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| [terraform/environments/temporal-test/main.tf](terraform/environments/temporal-test/main.tf)           | VPC, subnet, IAM, security group, and EC2 resources for this environment. |
| [terraform/environments/temporal-test/variables.tf](terraform/environments/temporal-test/variables.tf) | Inputs such as `my_ip`, instance settings, and optional keypair.          |
| [terraform/environments/temporal-test/outputs.tf](terraform/environments/temporal-test/outputs.tf)     | Runtime outputs (public IP, endpoints, helper commands).                  |
| [terraform/environments/temporal-test/backend.tf](terraform/environments/temporal-test/backend.tf)     | Remote-state backend configuration.                                       |
| [terraform/scripts/temporal-startup.sh](terraform/scripts/temporal-startup.sh)                         | EC2 bootstrap script that installs Docker and starts stack services.      |
| [terraform/temporal-compose/docker-compose.yml](terraform/temporal-compose/docker-compose.yml)         | Compose definition used by startup path.                                  |

## Deploy

```bash
cd terraform/environments/temporal-test

# Optional local-only validation
terraform init -backend=false
terraform validate

# Real deployment
terraform init
terraform plan -var="my_ip=$(curl -s ifconfig.me)/32"
terraform apply -var="my_ip=$(curl -s ifconfig.me)/32"
```

## Verify

After apply, use outputs to open the Temporal UI and test connectivity to the gRPC endpoint.

Suggested checks:

1. Open the emitted UI URL in browser.
2. Confirm namespace visibility via Temporal UI or CLI.
3. Confirm worker/runtime connectivity from your local client config.

## Destroy

```bash
cd terraform/environments/temporal-test
terraform destroy -var="my_ip=$(curl -s ifconfig.me)/32"
```
