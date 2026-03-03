# ──────────────────────────────────────────────────────────────
# VPC Module — Variables
# ──────────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of AZs to deploy subnets into"
  type        = list(string)
}

variable "extra_tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
