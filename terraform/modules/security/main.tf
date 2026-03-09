# ──────────────────────────────────────────────────────────────
# Security Module — IAM Roles, Security Groups, SSM Parameters
# ──────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ══════════════════════════════════════════════════════════════
# SECURITY GROUPS
# ══════════════════════════════════════════════════════════════

# ── Worker Security Group ────────────────────────────────────

resource "aws_security_group" "worker" {
  name_prefix = "${var.name_prefix}-worker-"
  description = "Security group for Temporal worker EC2 instances"
  vpc_id      = var.vpc_id

  # Outbound: allow all (ECR, CloudWatch, Temporal Cloud, RDS)
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-worker-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ── Database Security Group ──────────────────────────────────

resource "aws_security_group" "database" {
  name_prefix = "${var.name_prefix}-db-"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from workers"
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = [aws_security_group.worker.id]
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-db-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ── Lambda Security Group ────────────────────────────────────

resource "aws_security_group" "lambda" {
  name_prefix = "${var.name_prefix}-lambda-"
  description = "Security group for ingress Proxy Lambda (VPC-placed)"
  vpc_id      = var.vpc_id

  # Outbound: allow all (Temporal gRPC 7233, CloudWatch, etc.)
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-lambda-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ══════════════════════════════════════════════════════════════
# IAM — Worker EC2 Instance Profile
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "worker" {
  name = "${var.name_prefix}-worker-role"

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

  tags = var.extra_tags
}

# SSM Session Manager access (for SSH-less management)
resource "aws_iam_role_policy_attachment" "worker_ssm" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ECR pull access for container images
resource "aws_iam_role_policy_attachment" "worker_ecr" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# CloudWatch Logs
resource "aws_iam_role_policy" "worker_cloudwatch" {
  name = "${var.name_prefix}-worker-cloudwatch"
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# S3 evidence bucket access
resource "aws_iam_role_policy" "worker_s3" {
  name = "${var.name_prefix}-worker-s3"
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.evidence_bucket_arn,
          "${var.evidence_bucket_arn}/*"
        ]
      }
    ]
  })
}

# DynamoDB audit table access
resource "aws_iam_role_policy" "worker_dynamodb" {
  name = "${var.name_prefix}-worker-dynamodb"
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          var.audit_table_arn,
          "${var.audit_table_arn}/index/*"
        ]
      }
    ]
  })
}

# SSM Parameter Store read access (tenant secrets)
resource "aws_iam_role_policy" "worker_ssm_params" {
  name = "${var.name_prefix}-worker-ssm-params"
  role = aws_iam_role.worker.id

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
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.name_prefix}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "worker" {
  name = "${var.name_prefix}-worker-profile"
  role = aws_iam_role.worker.name

  tags = var.extra_tags
}

# ══════════════════════════════════════════════════════════════
# IAM — Ingress Lambda Execution Role
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "ingress_lambda" {
  name = "${var.name_prefix}-ingress-lambda-role"

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

  tags = var.extra_tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.ingress_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# VPC access — allows Lambda to create ENIs in the VPC
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.ingress_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Lambda needs to read SSM params and write to DynamoDB for request tracking
resource "aws_iam_role_policy" "lambda_ssm" {
  name = "${var.name_prefix}-lambda-ssm"
  role = aws_iam_role.ingress_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.name_prefix}/*"
      }
    ]
  })
}

# ══════════════════════════════════════════════════════════════
# SSM PARAMETER STORE — Secrets & Configuration
# ══════════════════════════════════════════════════════════════

# Database password stored in SSM (cost-effective vs Secrets Manager)
resource "aws_ssm_parameter" "db_password" {
  name        = "/${var.name_prefix}/database/password"
  description = "RDS PostgreSQL master password"
  type        = "SecureString"
  value       = "PLACEHOLDER" # Replaced by main.tf random_password

  tags = var.extra_tags

  lifecycle {
    ignore_changes = [value]
  }
}

# Temporal Cloud connection config
resource "aws_ssm_parameter" "temporal_address" {
  name        = "/${var.name_prefix}/temporal/address"
  description = "Temporal Cloud gRPC endpoint"
  type        = "String"
  value       = "PLACEHOLDER"

  tags = var.extra_tags

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "temporal_namespace" {
  name        = "/${var.name_prefix}/temporal/namespace"
  description = "Temporal Cloud namespace"
  type        = "String"
  value       = "PLACEHOLDER"

  tags = var.extra_tags

  lifecycle {
    ignore_changes = [value]
  }
}

# ══════════════════════════════════════════════════════════════
# IAM — Authorizer Lambda Execution Role
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "authorizer_lambda" {
  name = "${var.name_prefix}-authorizer-lambda-role"

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

  tags = var.extra_tags
}

resource "aws_iam_role_policy_attachment" "authorizer_basic" {
  role       = aws_iam_role.authorizer_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Allow API Gateway to invoke Lambda via authorizer credentials
resource "aws_iam_role_policy" "authorizer_invoke_lambda" {
  name = "${var.name_prefix}-authorizer-invoke-lambda"
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

resource "aws_iam_role_policy" "authorizer_ssm_policy" {
  name = "${var.name_prefix}-authorizer-ssm-policy"
  role = aws_iam_role.authorizer_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/secamo/tenants/*/api/*"
      },
      {
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
      }
    ]
  })
}
