output "vpc_id" {
  description = "VPC id for the demo VM environment"
  value       = aws_vpc.demo_vm.id
}

output "public_subnet_id" {
  description = "Public subnet id hosting the demo VM"
  value       = aws_subnet.public.id
}

output "vm_security_group_id" {
  description = "Security group id attached to the Windows VM"
  value       = aws_security_group.windows_vm.id
}

output "vm_instance_id" {
  description = "EC2 instance id for the Windows VM"
  value       = aws_instance.windows.id
}

output "vm_private_ip" {
  description = "Private IP address of the Windows VM"
  value       = aws_instance.windows.private_ip
}

output "vm_public_ip" {
  description = "Public IP address of the Windows VM (null when public_ip_enabled is false)"
  value       = var.public_ip_enabled ? aws_instance.windows.public_ip : null
}

output "rdp_endpoint" {
  description = "RDP endpoint host:port (null when public_ip_enabled is false)"
  value       = var.public_ip_enabled ? "${aws_instance.windows.public_ip}:3389" : null
}

output "ssm_start_session_command" {
  description = "AWS CLI command to open an SSM session to the VM"
  value       = "aws ssm start-session --target ${aws_instance.windows.id}"
}

output "windows_ami_id" {
  description = "AMI id used by the Windows VM"
  value       = aws_instance.windows.ami
}
