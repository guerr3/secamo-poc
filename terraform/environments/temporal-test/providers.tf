# ──────────────────────────────────────────────────────────────
# Providers — temporal-test (standalone Temporal on EC2)
# ──────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "secamo-temporal-test"
      Environment = "test"
      ManagedBy   = "terraform"
    }
  }
}
