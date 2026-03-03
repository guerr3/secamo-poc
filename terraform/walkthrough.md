# Terraform Infrastructure Scaffolding — Walkthrough

## What Was Built

Complete Terraform folder structure for the **secamo-poc** cost-optimized v1.2 architecture (~$42/mo target), containing **25 files** across 6 modules.

## Directory Tree

```
terraform/
├── .gitignore
├── environments/poc/     ← Root config (5 files)
├── modules/
│   ├── vpc/              ← VPC + fck-nat (t4g.nano)
│   ├── ingress/          ← API Gateway HTTP API + Lambda
│   ├── compute/          ← EC2 t3.medium Temporal workers
│   ├── database/         ← RDS PostgreSQL db.t4g.small
│   ├── storage/          ← S3 evidence + DynamoDB audit
│   └── security/         ← IAM roles, SGs, SSM params
└── scripts/
    └── worker-startup.sh ← EC2 bootstrap script
```

## Architecture Decisions

| Component | Implementation | Cost Rationale |
|-----------|---------------|----------------|
| NAT | `fck-nat` on `t4g.nano` | ~$3/mo vs $32/mo NAT Gateway |
| Ingress | API Gateway HTTP API + Lambda | Pay-per-request vs ~$16/mo ALB |
| Compute | `t3.medium` EC2 (On-Demand) | Single worker, right-sized |
| Database | RDS PostgreSQL `db.t4g.small` | ARM-based, single-AZ |
| Secrets | SSM Parameter Store | Free tier vs $0.40/secret/mo |
| VPC Endpoints | None | Traffic routes via fck-nat |

## Key Highlights

- **Security**: IMDSv2 enforced on EC2, least-privilege IAM policies, KMS-encrypted S3, encrypted RDS
- **VPC**: Public + private subnet per AZ, fck-nat with source/dest check disabled
- **Ingress**: Route `ANY /api/v1/ingress/{proxy+}` → Python 3.11 ARM64 Lambda
- **Storage**: DynamoDB single-table design (PK/SK + GSI1) with PITR enabled
- **State**: S3 + DynamoDB backend with encryption and state locking

## Next Steps

> [!IMPORTANT]
> Before running `terraform init`:
> 1. Create the S3 state bucket and DynamoDB lock table manually
> 2. Create a placeholder `placeholder.zip` in `modules/ingress/` (or update the Lambda source)
> 3. Update the S3 backend bucket name in [backend.tf](file:///c:/Users/ghost/Documents/codebases/secamo-poc/terraform/environments/poc/backend.tf) with your account ID suffix

## Verification

✅ All 25 files generated and directory tree matches specification exactly.
