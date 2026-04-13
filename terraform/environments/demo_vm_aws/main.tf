locals {
  common_tags = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.extra_tags,
  )

  resolved_availability_zone = var.availability_zone != "" ? var.availability_zone : data.aws_availability_zones.available.names[0]
  resolved_windows_ami       = var.windows_ami_id != "" ? var.windows_ami_id : data.aws_ami.windows_server_2022.id
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "windows_server_2022" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_key_pair" "windows_access" {
  key_name = var.key_pair_name
}

resource "aws_vpc" "demo_vm" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-vpc"
  })
}

resource "aws_internet_gateway" "demo_vm" {
  vpc_id = aws_vpc.demo_vm.id

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-igw"
  })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.demo_vm.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = local.resolved_availability_zone
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-public-${local.resolved_availability_zone}"
    Tier = "public"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.demo_vm.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo_vm.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-public-rt"
  })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "windows_vm" {
  name_prefix = "${var.name_prefix}-vm-"
  description = "Security group for the demo Windows VM"
  vpc_id      = aws_vpc.demo_vm.id

  ingress {
    description = "RDP from allowed CIDR"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.rdp_allowed_cidr]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-vm-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "vm" {
  name = "${var.name_prefix}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "vm_ssm" {
  role       = aws_iam_role.vm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "vm" {
  name = "${var.name_prefix}-profile"
  role = aws_iam_role.vm.name

  tags = local.common_tags
}

resource "aws_instance" "windows" {
  ami                         = local.resolved_windows_ami
  instance_type               = var.windows_instance_type
  subnet_id                   = aws_subnet.public.id
  associate_public_ip_address = var.public_ip_enabled
  vpc_security_group_ids      = [aws_security_group.windows_vm.id]
  iam_instance_profile        = aws_iam_instance_profile.vm.name
  key_name                    = data.aws_key_pair.windows_access.key_name
  get_password_data           = true

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size_gb
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tags = merge(local.common_tags, {
    Name = var.instance_name
    Role = "demo-windows-vm"
  })

  depends_on = [
    aws_route_table_association.public,
    aws_iam_role_policy_attachment.vm_ssm,
  ]
}
