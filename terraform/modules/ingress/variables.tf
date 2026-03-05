# ──────────────────────────────────────────────────────────────
# Ingress Module — Variables
# ──────────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "lambda_memory" {
  description = "Proxy Lambda memory allocation in MB"
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Proxy Lambda timeout in seconds"
  type        = number
  default     = 30
}

variable "lambda_role_arn" {
  description = "IAM role ARN for the Proxy Lambda execution role"
  type        = string
}

variable "authorizer_role_arn" {
  description = "IAM role ARN for the Authorizer Lambda execution role"
  type        = string
}

# ── VPC Configuration (for Proxy Lambda) ────────────────────

variable "private_subnet_ids" {
  description = "Private subnet IDs for the Proxy Lambda VPC placement"
  type        = list(string)
}

variable "lambda_sg_id" {
  description = "Security Group ID for the Proxy Lambda"
  type        = string
}

# ── Temporal Configuration ──────────────────────────────────

variable "temporal_host" {
  description = "Temporal Server gRPC address (host:port)"
  type        = string
}

variable "temporal_namespace" {
  description = "Temporal namespace to target"
  type        = string
  default     = "default"
}

# ── Resource Policy ─────────────────────────────────────────

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to invoke the API (e.g. Microsoft IP ranges)"
  type        = list(string)
  default     = ["20.190.128.0/18", "40.126.0.0/18"]
}

# ── Tags ────────────────────────────────────────────────────

variable "extra_tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
