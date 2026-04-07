variable "project_name" {
  description = "Project tag/name prefix for demo tenant resources"
  type        = string
  default     = "secamo"
}

variable "environment" {
  description = "Environment identifier for tagging and naming"
  type        = string
  default     = "demo_tenant"
}

variable "extra_tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "tenant_id" {
  description = "Tenant identifier used in SSM path and platform tenant context"
  type        = string
}

variable "tenant_display_name" {
  description = "Human-readable tenant display name"
  type        = string
}

variable "aws_region" {
  description = "AWS region for SSM Parameter Store resources"
  type        = string
  default     = "eu-west-1"
}

variable "aws_profile" {
  description = "Optional AWS profile for local Terraform execution"
  type        = string
  default     = ""
}

variable "ssm_kms_key_id" {
  description = "Optional KMS key id/arn for SecureString parameters (leave empty for AWS managed key)"
  type        = string
  default     = ""
}

variable "iam_provider" {
  description = "TenantConfig IAM provider"
  type        = string
  default     = "microsoft_graph"
}

variable "edr_provider" {
  description = "TenantConfig EDR provider"
  type        = string
  default     = "microsoft_defender"
}

variable "ticketing_provider" {
  description = "TenantConfig ticketing provider"
  type        = string
  default     = "jira"
}

variable "threat_intel_providers" {
  description = "Comma-separated threat intel providers for TenantConfig"
  type        = string
  default     = "virustotal,abuseipdb"
}

variable "notification_provider" {
  description = "TenantConfig notification provider"
  type        = string
  default     = "teams"
}

variable "soc_analyst_email" {
  description = "SOC analyst mailbox used for HiTL reviewer routing"
  type        = string
}

variable "sla_tier" {
  description = "TenantConfig SLA tier"
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["platinum", "standard", "basic"], var.sla_tier)
    error_message = "sla_tier must be one of: platinum, standard, basic."
  }
}

variable "hitl_timeout_hours" {
  description = "TenantConfig HiTL timeout in hours"
  type        = number
  default     = 4
}

variable "escalation_enabled" {
  description = "TenantConfig escalation flag"
  type        = bool
  default     = true
}

variable "auto_isolate_on_timeout" {
  description = "TenantConfig auto-isolate timeout behavior"
  type        = bool
  default     = false
}

variable "max_activity_attempts" {
  description = "TenantConfig max activity retry attempts"
  type        = number
  default     = 3
}

variable "threat_intel_enabled" {
  description = "TenantConfig threat intel enablement"
  type        = bool
  default     = true
}

variable "evidence_bundle_enabled" {
  description = "TenantConfig evidence bundle enablement"
  type        = bool
  default     = true
}

variable "auto_ticket_creation" {
  description = "TenantConfig automatic ticket creation"
  type        = bool
  default     = true
}

variable "misp_sharing_enabled" {
  description = "TenantConfig MISP sharing enablement"
  type        = bool
  default     = false
}

variable "polling_providers" {
  description = "TenantConfig polling_providers CSV string"
  type        = string
  default     = "microsoft_defender:defender_alerts:graph:300,jira:tickets:ticketing:300"
}

variable "graph_subscriptions" {
  description = "TenantConfig graph_subscriptions CSV or JSON string"
  type        = string
  default     = "security/alerts_v2:created+updated:false:24,auditLogs/signIns:created+updated:false:24"
}

variable "graph_client_id" {
  description = "Microsoft Graph app registration client id"
  type        = string
  sensitive   = true
}

variable "graph_client_secret" {
  description = "Microsoft Graph app registration client secret"
  type        = string
  sensitive   = true
}

variable "graph_tenant_azure_id" {
  description = "Azure/Entra tenant id used by Graph and Defender"
  type        = string
  sensitive   = true
}

variable "ticketing_jira_base_url" {
  description = "Jira base URL"
  type        = string
}

variable "ticketing_jira_email" {
  description = "Jira technical user email"
  type        = string
}

variable "ticketing_jira_api_token" {
  description = "Jira API token"
  type        = string
  sensitive   = true
}

variable "ticketing_project_key" {
  description = "Jira project key used by ticketing adapter"
  type        = string
}

variable "ticketing_project_type" {
  description = "Jira project type used by ticketing adapter"
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["standard", "jsm"], var.ticketing_project_type)
    error_message = "ticketing_project_type must be 'standard' or 'jsm'."
  }
}

variable "ticketing_jsm_service_desk_id" {
  description = "Optional JSM service desk id"
  type        = string
  default     = ""
}

variable "chatops_teams_webhook_url" {
  description = "Teams webhook URL for chatops notifications"
  type        = string
  sensitive   = true
}

variable "threatintel_virustotal_api_key" {
  description = "VirusTotal API key"
  type        = string
  sensitive   = true
}

variable "threatintel_abuseipdb_api_key" {
  description = "AbuseIPDB API key"
  type        = string
  sensitive   = true
}

variable "hitl_jira_webhook_secret" {
  description = "Shared secret used by /api/v1/hitl/jira/{tenant_id} ingress validation"
  type        = string
  sensitive   = true
}

variable "hitl_endpoint_base_url" {
  description = "Tenant-scoped HiTL endpoint base URL metadata"
  type        = string
}

variable "webhooks_jira_secret" {
  description = "Shared secret used by generic Jira webhook auth validator"
  type        = string
  sensitive   = true
}

variable "azure_subscription_id" {
  description = "Azure subscription id for demo tenant resources"
  type        = string
}

variable "azure_tenant_id" {
  description = "Azure tenant id used by azurerm provider authentication context"
  type        = string
}

variable "azure_client_id" {
  description = "Optional Azure service principal client id for Terraform auth (leave empty to use CLI/session auth)"
  type        = string
  default     = ""
}

variable "azure_client_secret" {
  description = "Optional Azure service principal client secret for Terraform auth"
  type        = string
  default     = ""
  sensitive   = true
}

variable "azure_skip_provider_registration" {
  description = "Set true if provider registration is centrally managed in your tenant"
  type        = bool
  default     = false
}

variable "azure_location" {
  description = "Azure region for VM resources"
  type        = string
  default     = "westeurope"
}

variable "azure_resource_group_name" {
  description = "Azure resource group name for demo tenant resources"
  type        = string
}

variable "azure_vnet_cidr" {
  description = "CIDR for Azure virtual network"
  type        = string
  default     = "10.220.0.0/16"
}

variable "azure_subnet_cidr" {
  description = "CIDR for Azure VM subnet"
  type        = string
  default     = "10.220.10.0/24"
}

variable "azure_vm_name" {
  description = "Azure Windows VM name"
  type        = string
  default     = "secamo-demo-windows"
}

variable "azure_vm_size" {
  description = "Azure VM size (cost-optimized default for demo use)"
  type        = string
  default     = "Standard_B2s"
}

variable "azure_vm_admin_username" {
  description = "Local administrator username for the Windows VM"
  type        = string
  default     = "secamoadmin"
}

variable "azure_vm_admin_password" {
  description = "Local administrator password for the Windows VM"
  type        = string
  sensitive   = true
}

variable "azure_admin_allowed_cidr" {
  description = "Source CIDR allowed to RDP to the VM"
  type        = string
  default     = "0.0.0.0/0"
}

variable "azure_public_ip_enabled" {
  description = "Whether to allocate a public IP for demo VM access"
  type        = bool
  default     = true
}

variable "defender_for_servers_subplan" {
  description = "Defender for Servers subplan (P1 or P2)"
  type        = string
  default     = "P1"

  validation {
    condition     = contains(["P1", "P2"], var.defender_for_servers_subplan)
    error_message = "defender_for_servers_subplan must be P1 or P2."
  }
}
