# ──────────────────────────────────────────────────────────────
# Ingress Module — Variables
# ──────────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "lambda_memory" {
  description = "Lambda memory allocation in MB"
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 30
}

variable "lambda_role_arn" {
  description = "IAM role ARN for the Lambda execution role"
  type        = string
}

variable "extra_tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
