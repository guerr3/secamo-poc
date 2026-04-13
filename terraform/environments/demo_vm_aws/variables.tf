variable "project_name" {
  description = "Project tag/name prefix for demo VM resources"
  type        = string
  default     = "secamo"
}

variable "environment" {
  description = "Environment identifier for tagging and naming"
  type        = string
  default     = "demo_vm_aws"
}

variable "name_prefix" {
  description = "Name prefix used for AWS resource names"
  type        = string
  default     = "secamo-demo-vm-aws"
}

variable "extra_tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "aws_region" {
  description = "AWS region for all demo VM resources"
  type        = string
  default     = "eu-west-1"
}

variable "aws_profile" {
  description = "Optional AWS profile for local Terraform execution"
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "CIDR block for the demo VPC"
  type        = string
  default     = "10.230.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet hosting the demo VM"
  type        = string
  default     = "10.230.10.0/24"
}

variable "availability_zone" {
  description = "Optional availability zone override (leave empty for first available zone in region)"
  type        = string
  default     = ""
}

variable "rdp_allowed_cidr" {
  description = "Source CIDR allowed to RDP to the VM on port 3389"
  type        = string
  default     = "0.0.0.0/0"

  validation {
    condition     = can(cidrhost(var.rdp_allowed_cidr, 0))
    error_message = "rdp_allowed_cidr must be a valid CIDR (for example 203.0.113.10/32)."
  }
}

variable "public_ip_enabled" {
  description = "Whether to allocate a public IP for direct RDP access"
  type        = bool
  default     = true
}

variable "windows_instance_type" {
  description = "EC2 instance type for the Windows Server VM"
  type        = string
  default     = "t3.large"
}

variable "root_volume_size_gb" {
  description = "Root EBS volume size in GiB"
  type        = number
  default     = 50
}

variable "key_pair_name" {
  description = "EC2 key pair name required for Windows Administrator password retrieval"
  type        = string

  validation {
    condition     = trimspace(var.key_pair_name) != ""
    error_message = "key_pair_name is required. AWS can only provide the Windows Administrator password when the instance is launched with a key pair."
  }
}

variable "windows_ami_id" {
  description = "Optional Windows AMI override (leave empty to use latest Windows Server 2022)"
  type        = string
  default     = ""
}

variable "instance_name" {
  description = "Name tag value for the EC2 instance"
  type        = string
  default     = "secamo-demo-win-01"
}
