# ──────────────────────────────────────────────────────────────
# Security Module — Variables
# ──────────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for security groups"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs"
  type        = list(string)
}

variable "db_port" {
  description = "Database port"
  type        = number
  default     = 5432
}

variable "evidence_bucket_arn" {
  description = "ARN of the S3 evidence bucket"
  type        = string
}

variable "audit_table_arn" {
  description = "ARN of the DynamoDB audit table"
  type        = string
}

variable "extra_tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
