# demo_vm_aws Environment

Standalone AWS Windows VM environment for demo and endpoint testing scenarios.

## What This Environment Provisions

- Dedicated VPC, subnet, route table, and internet gateway.
- Security group with configurable RDP allowlist.
- IAM instance profile for Session Manager connectivity.
- One Windows EC2 VM intended for manual endpoint onboarding.

This environment is intentionally isolated from shared platform runtime resources.

## Scope Guardrails

- AWS only.
- No tenant SSM configuration writes.
- No shared ingress/worker/storage stack deployment.
- No automatic Defender for Endpoint onboarding.

## Prerequisites

1. Terraform 1.6+.
2. Authenticated AWS session.
3. Existing remote Terraform backend primitives used by this repository.
4. Existing EC2 key pair (required by this environment for Windows password retrieval).

## File Map

- `backend.tf`: isolated remote state configuration.
- `providers.tf`: AWS provider setup.
- `variables.tf`: input surface for networking, access, and compute.
- `main.tf`: network, IAM profile, and Windows VM resources.
- `outputs.tf`: connectivity/resource outputs.
- `demo_vm_aws.tfvars.example`: input template.

## Usage

```powershell
cd terraform/environments/demo_vm_aws
copy demo_vm_aws.tfvars.example demo_vm_aws.tfvars
terraform init
terraform fmt -check
terraform validate
terraform plan -var-file="demo_vm_aws.tfvars"
terraform apply -var-file="demo_vm_aws.tfvars"
```

## Post-Deploy Verification

1. Validate outputs (`vm_instance_id`, `vm_public_ip`, `rdp_endpoint`, `ssm_start_session_command`).
2. Confirm port 3389 exposure matches `rdp_allowed_cidr`.
3. Confirm SSM session connectivity.

## Windows Password Retrieval Requirement

AWS only exposes decryptable Windows Administrator password data when the instance was launched with a key pair.

- `key_pair_name` is required by this environment to prevent non-recoverable launch configs.
- If needed, force recreation with a valid key pair:

```powershell
terraform apply -var-file="demo_vm_aws.tfvars" -replace="aws_instance.windows"
```

## Manual Defender Onboarding

After deployment:

1. Access the VM via RDP or SSM.
2. Apply your Defender for Endpoint onboarding package/script.
3. Validate device status in your Defender portal.

## Notes

- Prefer SSM-only administration when possible (`public_ip_enabled=false`).
- Keep `rdp_allowed_cidr` narrow (ideally a single `/32` source).
