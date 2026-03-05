# ──────────────────────────────────────────────────────────────
# Root Configuration — Module Calls
# Cost-optimized v1.2 Architecture (~$42/mo target)
# ──────────────────────────────────────────────────────────────

locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# ── Random password for RDS ──────────────────────────────────

resource "random_password" "db_password" {
  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# ── Networking ───────────────────────────────────────────────

module "vpc" {
  source = "../../modules/vpc"

  name_prefix        = local.name_prefix
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  extra_tags         = var.extra_tags
}

# ── Security (IAM, SGs, SSM) ────────────────────────────────

module "security" {
  source = "../../modules/security"

  name_prefix         = local.name_prefix
  vpc_id              = module.vpc.vpc_id
  vpc_cidr            = var.vpc_cidr
  private_subnet_ids  = module.vpc.private_subnet_ids
  db_port             = 5432
  evidence_bucket_arn = module.storage.evidence_bucket_arn
  audit_table_arn     = module.storage.audit_table_arn
  extra_tags          = var.extra_tags
}

# ── Database (RDS PostgreSQL) ────────────────────────────────

module "database" {
  source = "../../modules/database"

  name_prefix          = local.name_prefix
  db_instance_class    = var.db_instance_class
  db_name              = var.db_name
  db_username          = var.db_username
  db_password          = random_password.db_password.result
  private_subnet_ids   = module.vpc.private_subnet_ids
  db_security_group_id = module.security.db_security_group_id
  extra_tags           = var.extra_tags
}

# ── Compute (EC2 Workers) ───────────────────────────────────

module "compute" {
  source = "../../modules/compute"

  name_prefix              = local.name_prefix
  instance_type            = var.worker_instance_type
  ami_id                   = var.worker_ami_id
  key_pair_name            = var.worker_key_pair_name
  private_subnet_id        = module.vpc.private_subnet_ids[0]
  worker_security_group_id = module.security.worker_security_group_id
  instance_profile_name    = module.security.worker_instance_profile_name
  db_endpoint              = module.database.db_endpoint
  db_name                  = var.db_name
  db_username              = var.db_username
  extra_tags               = var.extra_tags
}

# ── Ingress (API Gateway + Lambda) ──────────────────────────

module "ingress" {
  source = "../../modules/ingress"

  name_prefix     = local.name_prefix
  lambda_memory   = var.ingress_lambda_memory
  lambda_timeout  = var.ingress_lambda_timeout
  lambda_role_arn = module.security.ingress_lambda_role_arn
  extra_tags      = var.extra_tags
}

# ── Storage (S3 + DynamoDB) ─────────────────────────────────

module "storage" {
  source = "../../modules/storage"

  name_prefix          = local.name_prefix
  evidence_bucket_name = var.evidence_bucket_name
  extra_tags           = var.extra_tags
}
