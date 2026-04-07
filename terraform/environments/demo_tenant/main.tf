locals {
  tenant_ssm_prefix = "/secamo/tenants/${var.tenant_id}"

  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      TenantId    = var.tenant_id
      ManagedBy   = "terraform"
    },
    var.extra_tags,
  )

  config_parameters = {
    display_name            = var.tenant_display_name
    iam_provider            = var.iam_provider
    edr_provider            = var.edr_provider
    ticketing_provider      = var.ticketing_provider
    threat_intel_providers  = var.threat_intel_providers
    notification_provider   = var.notification_provider
    soc_analyst_email       = var.soc_analyst_email
    sla_tier                = var.sla_tier
    hitl_timeout_hours      = tostring(var.hitl_timeout_hours)
    escalation_enabled      = tostring(var.escalation_enabled)
    auto_isolate_on_timeout = tostring(var.auto_isolate_on_timeout)
    max_activity_attempts   = tostring(var.max_activity_attempts)
    threat_intel_enabled    = tostring(var.threat_intel_enabled)
    evidence_bundle_enabled = tostring(var.evidence_bundle_enabled)
    auto_ticket_creation    = tostring(var.auto_ticket_creation)
    misp_sharing_enabled    = tostring(var.misp_sharing_enabled)
    polling_providers       = var.polling_providers
    graph_subscriptions     = var.graph_subscriptions
  }

  tenant_string_parameters = merge(
    { for key, value in local.config_parameters : "config/${key}" => value },
    {
      "ticketing/jira_base_url"       = var.ticketing_jira_base_url
      "ticketing/jira_email"          = var.ticketing_jira_email
      "ticketing/project_key"         = var.ticketing_project_key
      "ticketing/project_type"        = var.ticketing_project_type
      "ticketing/jsm_service_desk_id" = var.ticketing_jsm_service_desk_id
      "hitl/endpoint_base_url"        = var.hitl_endpoint_base_url
    },
  )

  tenant_secure_parameters = {
    "graph/client_id"                = var.graph_client_id
    "graph/client_secret"            = var.graph_client_secret
    "graph/tenant_azure_id"          = var.graph_tenant_azure_id
    "ticketing/jira_api_token"       = var.ticketing_jira_api_token
    "chatops/teams_webhook_url"      = var.chatops_teams_webhook_url
    "threatintel/virustotal_api_key" = var.threatintel_virustotal_api_key
    "threatintel/abuseipdb_api_key"  = var.threatintel_abuseipdb_api_key
    "hitl/jira_webhook_secret"       = var.hitl_jira_webhook_secret
    "webhooks/jira_secret"           = var.webhooks_jira_secret
  }

  secure_parameter_keys = toset([
    "graph/client_id",
    "graph/client_secret",
    "graph/tenant_azure_id",
    "ticketing/jira_api_token",
    "chatops/teams_webhook_url",
    "threatintel/virustotal_api_key",
    "threatintel/abuseipdb_api_key",
    "hitl/jira_webhook_secret",
    "webhooks/jira_secret",
  ])

  non_empty_string_parameters = {
    for key, value in local.tenant_string_parameters : key => value
    if trimspace(value) != ""
  }

}

resource "aws_ssm_parameter" "tenant_string_parameters" {
  for_each = local.non_empty_string_parameters

  name      = "${local.tenant_ssm_prefix}/${each.key}"
  type      = "String"
  value     = each.value
  overwrite = true

  tags = merge(local.common_tags, {
    Name = "${var.tenant_id}-${replace(each.key, "/", "-")}"
  })
}

resource "aws_ssm_parameter" "tenant_secure_parameters" {
  for_each = local.secure_parameter_keys

  name      = "${local.tenant_ssm_prefix}/${each.value}"
  type      = "SecureString"
  key_id    = var.ssm_kms_key_id != "" ? var.ssm_kms_key_id : null
  value     = local.tenant_secure_parameters[each.value]
  overwrite = true

  tags = merge(local.common_tags, {
    Name = "${var.tenant_id}-${replace(each.value, "/", "-")}"
  })
}

resource "azurerm_resource_group" "demo_tenant" {
  name     = var.azure_resource_group_name
  location = var.azure_location
  tags     = local.common_tags
}

resource "azurerm_virtual_network" "demo_tenant" {
  name                = "${var.azure_resource_group_name}-vnet"
  location            = azurerm_resource_group.demo_tenant.location
  resource_group_name = azurerm_resource_group.demo_tenant.name
  address_space       = [var.azure_vnet_cidr]
  tags                = local.common_tags
}

resource "azurerm_subnet" "demo_tenant" {
  name                 = "demo-subnet"
  resource_group_name  = azurerm_resource_group.demo_tenant.name
  virtual_network_name = azurerm_virtual_network.demo_tenant.name
  address_prefixes     = [var.azure_subnet_cidr]
}

resource "azurerm_network_security_group" "demo_tenant" {
  name                = "${var.azure_resource_group_name}-nsg"
  location            = azurerm_resource_group.demo_tenant.location
  resource_group_name = azurerm_resource_group.demo_tenant.name
  tags                = local.common_tags

  security_rule {
    name                       = "Allow-RDP-Restricted"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.azure_admin_allowed_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "demo_tenant" {
  count = var.azure_public_ip_enabled ? 1 : 0

  name                = "${var.azure_resource_group_name}-pip"
  location            = azurerm_resource_group.demo_tenant.location
  resource_group_name = azurerm_resource_group.demo_tenant.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.common_tags
}

resource "azurerm_network_interface" "demo_tenant" {
  name                = "${var.azure_vm_name}-nic"
  location            = azurerm_resource_group.demo_tenant.location
  resource_group_name = azurerm_resource_group.demo_tenant.name
  tags                = local.common_tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.demo_tenant.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = var.azure_public_ip_enabled ? azurerm_public_ip.demo_tenant[0].id : null
  }
}

resource "azurerm_network_interface_security_group_association" "demo_tenant" {
  network_interface_id      = azurerm_network_interface.demo_tenant.id
  network_security_group_id = azurerm_network_security_group.demo_tenant.id
}

resource "azurerm_windows_virtual_machine" "demo_tenant" {
  name                = var.azure_vm_name
  location            = azurerm_resource_group.demo_tenant.location
  resource_group_name = azurerm_resource_group.demo_tenant.name
  size                = var.azure_vm_size

  admin_username = var.azure_vm_admin_username
  admin_password = var.azure_vm_admin_password

  network_interface_ids = [azurerm_network_interface.demo_tenant.id]

  os_disk {
    name                 = "${var.azure_vm_name}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

resource "azurerm_virtual_machine_extension" "entra_login" {
  name                 = "AADLoginForWindows"
  virtual_machine_id   = azurerm_windows_virtual_machine.demo_tenant.id
  publisher            = "Microsoft.Azure.ActiveDirectory"
  type                 = "AADLoginForWindows"
  type_handler_version = "2.2"

  auto_upgrade_minor_version = true
  tags                       = local.common_tags
}

resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  resource_type = "VirtualMachines"
  tier          = "Standard"
  subplan       = var.defender_for_servers_subplan
}

resource "azurerm_security_center_auto_provisioning" "defender_agent" {
  auto_provision = "On"
}
