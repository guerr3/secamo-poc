# demo_tenant Environment

Tenant-scoped demo environment that writes tenant config/secrets in AWS SSM and provisions Azure VM resources for endpoint and onboarding scenarios.

## What This Environment Provisions

- Tenant-scoped SSM config and secret parameters under `/secamo/tenants/{tenant_id}`.
- Azure resource group, network, Windows VM, and Entra login extension.
- Defender for Servers subscription pricing and auto-provisioning controls in Azure.

This environment is isolated from other Terraform environments through its own backend state key.

## Prerequisites

1. Terraform 1.6+.
2. Authenticated AWS and Azure sessions.
3. Existing remote Terraform backend primitives used by this repository.
4. Azure permissions for VM/network creation and Defender for Cloud pricing/auto-provisioning.
5. Existing ingress + worker runtime already deployed separately.

## File Map

- `backend.tf`: isolated remote state configuration.
- `providers.tf`: AWS and Azure providers.
- `main.tf`: tenant SSM parameter writes and Azure resources.
- `variables.tf`: tenant and environment input surface.
- `outputs.tf`: verification outputs.
- `demo_tenant.tfvars.example`: input template.

## Usage

```powershell
cd terraform/environments/demo_tenant
copy demo_tenant.tfvars.example demo_tenant.tfvars
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file="demo_tenant.tfvars"
terraform apply -var-file="demo_tenant.tfvars"
```

## Post-Deploy Verification

1. Check Terraform outputs (`tenant_id`, SSM path prefix, Azure VM identifiers/IPs).
2. Verify tenant parameters under `/secamo/tenants/{tenant_id}/`.
3. Verify Azure VM login and Defender onboarding posture.

## End-to-End Event Validation

1. Generate a controlled Defender test signal/alert for the tenant.
2. Confirm the event is available in provider telemetry.
3. Send or allow ingress flow for the same `tenant_id`.
4. Validate Temporal executions:
   - `SocAlertTriageWorkflow` for alert/impossible-travel/default security-signal flow.
   - Dedicated signal workflows for mapped signal subtypes (`signin_log`, `risky_user`, `noncompliant_device`, `audit_log`).
5. Verify downstream side effects (ticketing, notification, audit/evidence where applicable).

## Notes

- Graph subscription creation in onboarding is best-effort/non-blocking.
- Polling renewal behavior is driven by tenant polling config (`poll_types` including `graph_subscription_renewal`).
- This environment writes tenant-scoped paths only; shared/global infrastructure resources are managed elsewhere.
