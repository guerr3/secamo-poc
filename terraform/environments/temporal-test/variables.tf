# ──────────────────────────────────────────────────────────────
# Variables — temporal-test
# ──────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-west-1"
}

variable "my_ip" {
  description = "Your public IP in CIDR notation (e.g. 1.2.3.4/32) to restrict SSH/UI/gRPC access"
  type        = string

  validation {
    condition     = can(cidrhost(var.my_ip, 0))
    error_message = "my_ip must be a valid CIDR (e.g. 203.0.113.10/32)."
  }
}

variable "instance_type" {
  description = "EC2 instance type for the Temporal server"
  type        = string
  default     = "t3.large"
}

variable "key_pair_name" {
  description = "EC2 Key Pair name for SSH access (leave empty to disable SSH key auth, SSM still works)"
  type        = string
  default     = ""
}

variable "temporal_namespace" {
  description = "Temporal namespace to create on boot"
  type        = string
  default     = "default"
}

variable "volume_size" {
  description = "Root EBS volume size in GB"
  type        = number
  default     = 30
}

# ── GitHub ───────────────────────────────────────────────────

variable "github_repo_url" {
  description = "GitHub repo URL for secamo-poc (HTTPS)"
  type        = string
  default     = "https://github.com/guerr3/secamo-poc.git"
}

# ── Worker Secrets (Graph API) ───────────────────────────────
# Secrets are now fetched dynamically from AWS SSM Parameter Store
# under the path: /secamo/tenants/*/graph/

# ── Ingress (Front Door) ─────────────────────────────────────

variable "microsoft_allowed_cidrs" {
  description = "Microsoft IP ranges allowed to invoke the ingress API"
  type        = list(string)
  default     = ["20.190.128.0/18", "40.126.0.0/18"]
}

variable "evidence_bucket_name" {
  description = "Optional override for the evidence S3 bucket name"
  type        = string
  default     = ""
}
