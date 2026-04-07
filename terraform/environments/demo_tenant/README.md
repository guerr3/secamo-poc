# demo_tenant Terraform environment

## Purpose
This environment provisions a fully isolated tenant footprint for a real MSP demo customer:
- AWS SSM tenant config + secrets under /secamo/tenants/{tenant_id}
- Azure Windows VM for demo/test endpoint scenarios
- Entra VM login extension and Defender for Servers auto-provisioning controls

This environment does not modify poc or temporal-test infrastructure and uses its own Terraform state key.

## Prerequisites
1. Terraform >= 1.6 and authenticated AWS + Azure sessions.
1. Existing remote Terraform backend primitives (S3 bucket + DynamoDB lock table) used by this repository.
1. Azure permissions at subscription scope for:
   - Microsoft.Security/pricings/write (Defender plan)
   - Microsoft.Security/autoProvisioningSettings/write
   - VM/network resource creation
1. Microsoft Defender for Cloud plan support in the target Azure subscription.
1. Entra ID + Intune tenant configuration for automatic MDM enrollment at join time:
   - Automatic MDM user scope enabled for target users/groups
   - Users allowed to join devices to Entra ID
1. Existing shared Secamo platform ingress/worker runtime deployed separately.

## Files
- backend.tf: isolated state key environments/demo_tenant/terraform.tfstate
- providers.tf: dual-provider aws + azurerm
- main.tf: SSM parameters and Azure resources
- variables.tf: typed input surface with sensitive flags
- outputs.tf: tenant and VM verification outputs
- demo_tenant.tfvars.example: full variable template

## Usage
1. Create a local tfvars file from the example.

```powershell
cd terraform/environments/demo_tenant
copy demo_tenant.tfvars.example demo_tenant.tfvars
```

2. Fill in real credentials and tenant-specific values in demo_tenant.tfvars.

3. Initialize and apply.

```powershell
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file="demo_tenant.tfvars"
terraform apply -var-file="demo_tenant.tfvars"
```

## Post-deploy verification
1. Confirm outputs for tenant_id, tenant_ssm_path_prefix, azure_vm_resource_id, and VM IP addresses.
1. Verify SSM keys exist under /secamo/tenants/{tenant_id}/.
1. Log in to the VM and confirm:
   - Entra sign-in extension is installed
   - Device appears in Intune (when MDM scope is configured)
   - Device appears in Defender for Endpoint through Defender for Servers onboarding

## Triggering a test alert end-to-end
1. On the Windows VM, generate a Microsoft Defender test alert (for example, using the built-in Defender EICAR test string in a controlled test folder).
1. Confirm the alert appears in the tenant M365 Defender portal.
1. Send/allow ingress event flow for the same tenant_id through the shared Secamo API endpoint.
1. Validate workflow execution in Temporal (DefenderAlertEnrichmentWorkflow or ImpossibleTravelWorkflow depending on event type), then confirm ticketing/notification/audit side effects.

## Notes
- This environment writes only tenant-scoped SSM paths and does not manage shared HiTL prefix parameters.
- If your platform authorizer strictly requires a DynamoDB tenant table item, register the tenant_id there as a separate operational step.
