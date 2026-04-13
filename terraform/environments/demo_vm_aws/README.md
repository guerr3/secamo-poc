# demo_vm_aws Terraform environment

## Purpose

This environment provisions a standalone Windows Server VM on AWS for demo/testing scenarios:

- Dedicated VPC, public subnet, internet gateway, and route table
- Security group with RDP restricted to a configurable CIDR
- IAM instance profile with AmazonSSMManagedInstanceCore for Session Manager access
- Single Windows EC2 instance ready for manual onboarding to Microsoft Defender for Endpoint

This environment is isolated from poc, temporal-test, and demo_tenant state/resources.

## Scope Guardrails

- AWS only (no Azure providers or resources)
- No AWS SSM parameter writes
- No Defender auto-provisioning resources
- No shared platform ingress/worker/storage resources

## Prerequisites

1. Terraform >= 1.6 and authenticated AWS session.
1. Existing remote Terraform backend primitives used by this repository (S3 bucket + DynamoDB lock table).
1. Existing EC2 key pair if you intend to decrypt the generated Windows Administrator password for RDP.

## Files

- backend.tf: isolated state key environments/demo_vm_aws/terraform.tfstate
- providers.tf: AWS provider and default tagging
- variables.tf: typed input surface for network/access/compute
- main.tf: VPC, subnet, IGW, route table, security group, IAM profile, Windows VM
- outputs.tf: connectivity and resource identifiers
- demo_vm_aws.tfvars.example: full variable template

## Usage

1. Create a local tfvars file from the example.

```powershell
cd terraform/environments/demo_vm_aws
copy demo_vm_aws.tfvars.example demo_vm_aws.tfvars
```

2. Fill in real values in demo_vm_aws.tfvars (especially aws_profile, rdp_allowed_cidr, and key_pair_name).

3. Initialize and apply.

```powershell
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file="demo_vm_aws.tfvars"
terraform apply -var-file="demo_vm_aws.tfvars"
```

## Post-deploy verification

1. Confirm outputs for vm_instance_id, vm_public_ip, rdp_endpoint, and ssm_start_session_command.
1. Verify port 3389 is reachable only from rdp_allowed_cidr.
1. Start an SSM session to verify managed-instance connectivity.

## Important: Windows password retrieval behavior

AWS only returns the Windows Administrator password for instances launched with a key pair.

- If you launch without key_pair_name, the EC2 console cannot decrypt or show the Windows password.
- This environment now requires key_pair_name to prevent that misconfiguration.
- For an already-created instance without a key pair, recreate the instance with a valid key pair:

```powershell
terraform apply -var-file="demo_vm_aws.tfvars" -replace="aws_instance.windows"
```

After the replacement instance is running, use the EC2 console Get Windows Password action with the matching private key, or use AWS CLI get-password-data with your private key.

## Manual Microsoft Defender onboarding

This environment intentionally does not auto-onboard the VM into Defender for Endpoint. After deployment:

1. Log in to the VM (RDP or SSM).
1. Apply your organization standard Windows onboarding package/script for Microsoft Defender for Endpoint.
1. Validate device appearance and health in the Defender portal.

## Notes

- For stronger security, set public_ip_enabled to false and use SSM-only administration.
- Keep rdp_allowed_cidr as narrow as possible (for example, a single /32 client IP).
