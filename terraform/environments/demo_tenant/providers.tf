terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.116"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = merge(
      {
        Project     = var.project_name
        Environment = var.environment
        TenantId    = var.tenant_id
        ManagedBy   = "terraform"
      },
      var.extra_tags,
    )
  }
}

provider "azurerm" {
  features {}

  subscription_id            = var.azure_subscription_id
  tenant_id                  = var.azure_tenant_id
  client_id                  = var.azure_client_id != "" ? var.azure_client_id : null
  client_secret              = var.azure_client_secret != "" ? var.azure_client_secret : null
  skip_provider_registration = var.azure_skip_provider_registration
}
