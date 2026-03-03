# ──────────────────────────────────────────────────────────────
# Temporal Test — Single EC2 with Docker Compose
# ──────────────────────────────────────────────────────────────
# Standalone environment: no module dependencies.
# Deploys a single EC2 in a public subnet running the full
# Temporal stack (Server, PostgreSQL, UI) via docker-compose.
# ──────────────────────────────────────────────────────────────

locals {
  name_prefix = "secamo-temporal-test"
}

# ══════════════════════════════════════════════════════════════
# DATA SOURCES
# ══════════════════════════════════════════════════════════════

data "aws_availability_zones" "available" {
  state = "available"
}

# Latest Amazon Linux 2023 AMI
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ══════════════════════════════════════════════════════════════
# NETWORKING — Minimal VPC with 1 Public Subnet
# ══════════════════════════════════════════════════════════════

resource "aws_vpc" "temporal" {
  cidr_block           = "10.99.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "temporal" {
  vpc_id = aws_vpc.temporal.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.temporal.id
  cidr_block              = "10.99.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.temporal.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.temporal.id
  }

  tags = {
    Name = "${local.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ══════════════════════════════════════════════════════════════
# SECURITY GROUP — Restricted to your IP
# ══════════════════════════════════════════════════════════════

resource "aws_security_group" "temporal" {
  name_prefix = "${local.name_prefix}-"
  description = "Temporal test server - SSH, gRPC, UI"
  vpc_id      = aws_vpc.temporal.id

  # SSH
  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # Temporal gRPC
  ingress {
    description = "Temporal gRPC from my IP"
    from_port   = 7233
    to_port     = 7233
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # Temporal UI
  ingress {
    description = "Temporal UI from my IP"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  # All outbound (Docker pulls, updates)
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ══════════════════════════════════════════════════════════════
# IAM — Minimal Instance Profile (SSM access)
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "temporal" {
  name = "${local.name_prefix}-role"

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
}

# SSM Session Manager (SSH-less access)
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.temporal.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "temporal" {
  name = "${local.name_prefix}-profile"
  role = aws_iam_role.temporal.name
}

# ══════════════════════════════════════════════════════════════
# EC2 INSTANCE — Temporal Server (docker-compose)
# ══════════════════════════════════════════════════════════════

resource "aws_instance" "temporal" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.temporal.id]
  iam_instance_profile   = aws_iam_instance_profile.temporal.name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  user_data = base64encode(templatefile("${path.module}/../../scripts/temporal-startup.sh", {
    temporal_namespace = var.temporal_namespace
    github_repo_url    = var.github_repo_url
    graph_tenant1_id   = var.graph_tenant1_id
    graph_client1_id   = var.graph_client1_id
    graph_secret1_value = var.graph_secret1_value
    graph_secret1_id   = var.graph_secret1_id
  }))

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.volume_size
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2
    http_put_response_hop_limit = 2
  }

  tags = {
    Name = "${local.name_prefix}-server"
    Role = "temporal-server"
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}
