# ──────────────────────────────────────────────────────────────
# PoC-Specific Variables
# ──────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name (poc, staging, prod)"
  type        = string
  default     = "poc"
}

variable "project_name" {
  description = "Project identifier used in resource naming"
  type        = string
  default     = "secamo"
}

# ── Networking ───────────────────────────────────────────────

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "AZs to deploy subnets into (min 2 for RDS subnet group)"
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b"]
}

# ── Compute ──────────────────────────────────────────────────

variable "worker_instance_type" {
  description = "EC2 instance type for Temporal workers"
  type        = string
  default     = "t3.medium"
}

variable "worker_ami_id" {
  description = "AMI ID for the worker EC2 instance (Amazon Linux 2023)"
  type        = string
  default     = "" # Resolved via data source if empty
}

variable "worker_key_pair_name" {
  description = "EC2 Key Pair name for SSH access (optional)"
  type        = string
  default     = ""
}

# ── Database ─────────────────────────────────────────────────

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.small"
}

variable "db_name" {
  description = "Name of the Temporal persistence database"
  type        = string
  default     = "temporal"
}

variable "db_username" {
  description = "Master username for RDS"
  type        = string
  default     = "temporal_admin"
  sensitive   = true
}

# ── Ingress ──────────────────────────────────────────────────

variable "ingress_lambda_memory" {
  description = "Memory allocation (MB) for the ingress Lambda"
  type        = number
  default     = 256
}

variable "ingress_lambda_timeout" {
  description = "Timeout (seconds) for the ingress Lambda"
  type        = number
  default     = 30
}

# ── Storage ──────────────────────────────────────────────────

variable "evidence_bucket_name" {
  description = "S3 bucket name for evidence storage"
  type        = string
  default     = ""
}

# ── Tags ─────────────────────────────────────────────────────

variable "extra_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
