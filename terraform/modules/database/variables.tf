# ──────────────────────────────────────────────────────────────
# Database Module — Variables
# ──────────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.small"
}

variable "db_name" {
  description = "Name of the database to create"
  type        = string
}

variable "db_username" {
  description = "Master username"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "Master password"
  type        = string
  sensitive   = true
}

variable "private_subnet_ids" {
  description = "Subnet IDs for the DB subnet group"
  type        = list(string)
}

variable "db_security_group_id" {
  description = "Security group ID for RDS"
  type        = string
}

variable "extra_tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
