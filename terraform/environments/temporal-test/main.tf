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

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

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

  # Internal communication (SSM Agent, Docker)
  ingress {
    description = "Internal communication (SSM Agent, Docker)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
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

# SSM Parameter Store read access (tenant secrets)
resource "aws_iam_role_policy" "temporal_ssm_params" {
  name = "${local.name_prefix}-ssm-params"
  role = aws_iam_role.temporal.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${local.name_prefix}/*",
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/secamo/tenants/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
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

  user_data = templatefile("${path.module}/../../scripts/temporal-startup.sh", {
    temporal_namespace = var.temporal_namespace
    github_repo_url    = var.github_repo_url
  })

  user_data_replace_on_change = true

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
    ignore_changes = [ami]
  }

  depends_on = [
    aws_route_table_association.public,
    aws_iam_role_policy_attachment.ssm
  ]
}

# ══════════════════════════════════════════════════════════════
# PRIVATE SUBNETS (for VPC Lambda placement)
# ══════════════════════════════════════════════════════════════

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.temporal.id
  cidr_block        = cidrsubnet("10.99.0.0/16", 8, 100 + count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${local.name_prefix}-private-${data.aws_availability_zones.available.names[count.index]}"
    Tier = "private"
  }
}

# ── fck-nat Instance (cost-effective NAT for private subnets) ─

data "aws_ami" "fck_nat" {
  most_recent = true
  owners      = ["568608671756"]

  filter {
    name   = "name"
    values = ["fck-nat-al2023-*-arm64-ebs"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

resource "aws_security_group" "fck_nat" {
  name_prefix = "${local.name_prefix}-fck-nat-"
  description = "Security group for fck-nat instance"
  vpc_id      = aws_vpc.temporal.id

  ingress {
    description = "All traffic from private subnets"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [for s in aws_subnet.private : s.cidr_block]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-fck-nat-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_network_interface" "fck_nat" {
  subnet_id         = aws_subnet.public.id
  security_groups   = [aws_security_group.fck_nat.id]
  source_dest_check = false

  tags = {
    Name = "${local.name_prefix}-fck-nat-eni"
  }
}

resource "aws_instance" "fck_nat" {
  ami           = data.aws_ami.fck_nat.id
  instance_type = "t4g.nano"

  network_interface {
    network_interface_id = aws_network_interface.fck_nat.id
    device_index         = 0
  }

  tags = {
    Name = "${local.name_prefix}-fck-nat"
  }
}

resource "aws_eip" "fck_nat" {
  domain            = "vpc"
  network_interface = aws_network_interface.fck_nat.id

  tags = {
    Name = "${local.name_prefix}-fck-nat-eip"
  }

  depends_on = [
    aws_internet_gateway.temporal,
    aws_instance.fck_nat
  ]
}

# ── Private Route Table (via fck-nat) ────────────────────────

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.temporal.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_network_interface.fck_nat.id
  }

  tags = {
    Name = "${local.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count = 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ══════════════════════════════════════════════════════════════
# LAMBDA SECURITY GROUP + TEMPORAL SG INGRESS RULE
# ══════════════════════════════════════════════════════════════

resource "aws_security_group" "lambda" {
  name_prefix = "${local.name_prefix}-lambda-"
  description = "Security group for ingress Proxy Lambda"
  vpc_id      = aws_vpc.temporal.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-lambda-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Allow Lambda → Temporal Server on gRPC port
resource "aws_security_group_rule" "temporal_from_lambda" {
  type                     = "ingress"
  description              = "Temporal gRPC from Lambda"
  from_port                = 7233
  to_port                  = 7233
  protocol                 = "tcp"
  security_group_id        = aws_security_group.temporal.id
  source_security_group_id = aws_security_group.lambda.id
}

# ══════════════════════════════════════════════════════════════
# IAM — Ingress Lambda Roles
# ══════════════════════════════════════════════════════════════

# Proxy Lambda execution role
resource "aws_iam_role" "ingress_lambda" {
  name = "${local.name_prefix}-ingress-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.ingress_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.ingress_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Authorizer Lambda execution role
resource "aws_iam_role" "authorizer_lambda" {
  name = "${local.name_prefix}-authorizer-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "authorizer_basic" {
  role       = aws_iam_role.authorizer_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "authorizer_invoke_lambda" {
  name = "${local.name_prefix}-authorizer-invoke-lambda"
  role = aws_iam_role.authorizer_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "authorizer_ssm" {
  name = "${local.name_prefix}-authorizer-ssm"
  role = aws_iam_role.authorizer_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/secamo/tenants/*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

# ══════════════════════════════════════════════════════════════
# INGRESS MODULE — REST API + Proxy Lambda + Authorizer
# ══════════════════════════════════════════════════════════════

module "ingress" {
  source = "../../modules/ingress"

  name_prefix         = local.name_prefix
  lambda_role_arn     = aws_iam_role.ingress_lambda.arn
  authorizer_role_arn = aws_iam_role.authorizer_lambda.arn

  private_subnet_ids = aws_subnet.private[*].id
  lambda_sg_id       = aws_security_group.lambda.id

  temporal_host      = "${aws_instance.temporal.private_ip}:7233"
  temporal_namespace = var.temporal_namespace

  allowed_cidr_blocks = var.microsoft_allowed_cidrs
}

