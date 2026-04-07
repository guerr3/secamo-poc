output "tenant_id" {
  description = "Tenant id used for this deployment"
  value       = var.tenant_id
}

output "tenant_ssm_path_prefix" {
  description = "SSM prefix containing tenant config and secrets"
  value       = "/secamo/tenants/${var.tenant_id}"
}

output "azure_vm_resource_id" {
  description = "Azure resource id of the demo Windows VM"
  value       = azurerm_windows_virtual_machine.demo_tenant.id
}

output "azure_vm_public_ip" {
  description = "Public IP of the demo VM (null when disabled)"
  value       = var.azure_public_ip_enabled ? azurerm_public_ip.demo_tenant[0].ip_address : null
}

output "azure_vm_private_ip" {
  description = "Private IP of the demo VM"
  value       = azurerm_network_interface.demo_tenant.private_ip_address
}
