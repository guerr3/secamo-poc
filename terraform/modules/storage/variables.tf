# ──────────────────────────────────────────────────────────────
# Storage Module — Variables
# ──────────────────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "evidence_bucket_name" {
  description = "S3 bucket name override (auto-generated if empty)"
  type        = string
  default     = ""
}

variable "extra_tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
