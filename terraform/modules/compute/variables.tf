# ──────────────────────────────────────────────────────────────
# Compute Module — Variables
# ──────────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "ami_id" {
  description = "AMI ID (empty = latest Amazon Linux 2023)"
  type        = string
  default     = ""
}

variable "key_pair_name" {
  description = "EC2 Key Pair for SSH (optional)"
  type        = string
  default     = ""
}

variable "private_subnet_id" {
  description = "Subnet ID for the worker instance"
  type        = string
}

variable "worker_security_group_id" {
  description = "Security group ID for the worker"
  type        = string
}

variable "instance_profile_name" {
  description = "IAM instance profile name"
  type        = string
}

variable "db_endpoint" {
  description = "RDS endpoint for worker configuration"
  type        = string
}

variable "db_name" {
  description = "Database name for worker configuration"
  type        = string
}

variable "db_username" {
  description = "Database username for worker configuration"
  type        = string
  sensitive   = true
}

variable "extra_tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
