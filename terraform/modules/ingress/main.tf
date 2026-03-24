# ──────────────────────────────────────────────────────────────
# Ingress Module — REST API Gateway + Proxy Lambda (VPC) + Authorizer
# ──────────────────────────────────────────────────────────────
#
# Routes:  POST /api/v1/ingress/event/{tenant_id} → Proxy Lambda (provider webhooks)
#          POST /api/v1/ingress/internal          → Proxy Lambda (internal triggers)
#          GET  /api/v1/hitl/respond      → Proxy Lambda (signed HiTL callback)
#          POST /api/v1/hitl/jira         → Proxy Lambda (Jira webhook callback)
# Auth:    Lambda Authorizer (REQUEST type)
# Policy:  Resource Policy — deny all except allowed CIDRs

# ══════════════════════════════════════════════════════════════
# LAMBDA LAYER (ingress_sdk + temporalio)
# ══════════════════════════════════════════════════════════════

data "archive_file" "layer" {
  type        = "zip"
  source_dir  = "${path.module}/layers/ingress"
  output_path = "${path.module}/dist/layer.zip"
  excludes    = ["build.sh"]
}

locals {
  required_shared_subpackages = [
    "approval",
    "auth",
    "ingress",
    "models",
    "normalization",
    "providers",
    "routing",
    "temporal",
  ]
}

resource "aws_lambda_layer_version" "ingress" {
  filename                 = data.archive_file.layer.output_path
  layer_name               = "${var.name_prefix}-ingress-layer"
  description              = "Ingress SDK + Temporal gRPC Client (arm64)"
  compatible_runtimes      = ["python3.11"]
  compatible_architectures = ["arm64"]

  source_code_hash = data.archive_file.layer.output_base64sha256

  lifecycle {
    precondition {
      condition = alltrue([
        for pkg in local.required_shared_subpackages : fileexists("${path.module}/layers/ingress/python/shared/${pkg}/__init__.py")
      ])
      error_message = "Ingress layer is missing one or more required shared subpackages. Run terraform/modules/ingress/layers/ingress/build.sh (or build.ps1) before terraform apply."
    }
  }
}

# ══════════════════════════════════════════════════════════════
# PROXY LAMBDA (VPC-placed Temporal Client)
# ══════════════════════════════════════════════════════════════

data "archive_file" "proxy" {
  type        = "zip"
  source_dir  = "${path.module}/src/ingress"
  output_path = "${path.module}/dist/ingress.zip"
}

resource "aws_lambda_function" "proxy" {
  function_name = "${var.name_prefix}-ingress-proxy"
  role          = var.lambda_role_arn
  handler       = "handler.handler"
  runtime       = "python3.11"
  memory_size   = var.lambda_memory
  timeout       = var.lambda_timeout
  architectures = ["arm64"]
  layers        = [aws_lambda_layer_version.ingress.arn]

  filename         = data.archive_file.proxy.output_path
  source_code_hash = data.archive_file.proxy.output_base64sha256

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.lambda_sg_id]
  }

  environment {
    variables = {
      TEMPORAL_HOST          = var.temporal_host
      TEMPORAL_NAMESPACE     = var.temporal_namespace
      HITL_TOKEN_TABLE       = var.hitl_token_table
      HITL_TOKEN_TTL_SECONDS = tostring(var.hitl_token_ttl_seconds)
      LOG_LEVEL              = "INFO"
    }
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-ingress-proxy"
  })
}

resource "aws_cloudwatch_log_group" "proxy" {
  name              = "/aws/lambda/${aws_lambda_function.proxy.function_name}"
  retention_in_days = 7

  tags = var.extra_tags
}

# ══════════════════════════════════════════════════════════════
# AUTHORIZER LAMBDA
# ══════════════════════════════════════════════════════════════

data "archive_file" "authorizer" {
  type        = "zip"
  source_dir  = "${path.module}/src/authorizer"
  output_path = "${path.module}/dist/authorizer.zip"
}

resource "aws_lambda_function" "authorizer" {
  function_name = "${var.name_prefix}-ingress-authorizer"
  role          = var.authorizer_role_arn
  handler       = "handler.handler"
  runtime       = "python3.11"
  memory_size   = 128
  timeout       = 5
  architectures = ["arm64"]

  filename         = data.archive_file.authorizer.output_path
  source_code_hash = data.archive_file.authorizer.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-ingress-authorizer"
  })
}

resource "aws_cloudwatch_log_group" "authorizer" {
  name              = "/aws/lambda/${aws_lambda_function.authorizer.function_name}"
  retention_in_days = 7

  tags = var.extra_tags
}

# ══════════════════════════════════════════════════════════════
# REST API GATEWAY
# ══════════════════════════════════════════════════════════════

resource "aws_api_gateway_rest_api" "ingress" {
  name = "${var.name_prefix}-ingress-api"

  # Resource Policy: deny all, allow only specified CIDRs
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "execute-api:/*"
      }
    ]
  })

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-ingress-api"
  })
}

# ── Resource Path Hierarchy ─────────────────────────────────
# /api → /api/v1 → /api/v1/ingress → /api/v1/ingress/event/{tenant_id}
#                                    → /api/v1/ingress/internal
#                → /api/v1/hitl    → /api/v1/hitl/respond
#                                    → /api/v1/hitl/jira

resource "aws_api_gateway_resource" "api" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_rest_api.ingress.root_resource_id
  path_part   = "api"
}

resource "aws_api_gateway_resource" "v1" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.api.id
  path_part   = "v1"
}

resource "aws_api_gateway_resource" "ingress" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.v1.id
  path_part   = "ingress"
}

resource "aws_api_gateway_resource" "event" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.ingress.id
  path_part   = "event"
}

resource "aws_api_gateway_resource" "event_tenant" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.event.id
  path_part   = "{tenant_id}"
}

resource "aws_api_gateway_resource" "internal" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.ingress.id
  path_part   = "internal"
}

resource "aws_api_gateway_resource" "hitl" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.v1.id
  path_part   = "hitl"
}

resource "aws_api_gateway_resource" "hitl_respond" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.hitl.id
  path_part   = "respond"
}

resource "aws_api_gateway_resource" "hitl_jira" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id
  parent_id   = aws_api_gateway_resource.hitl.id
  path_part   = "jira"
}

# ── Lambda Authorizer ───────────────────────────────────────

resource "aws_api_gateway_authorizer" "lambda" {
  name                             = "${var.name_prefix}-authorizer"
  rest_api_id                      = aws_api_gateway_rest_api.ingress.id
  authorizer_uri                   = aws_lambda_function.authorizer.invoke_arn
  authorizer_credentials           = var.authorizer_role_arn
  type                             = "REQUEST"
  identity_source                  = "method.request.header.Authorization, method.request.header.x-tenant-id"
  authorizer_result_ttl_in_seconds = 0
}

# ── POST /api/v1/ingress/event/{tenant_id} ───────────────────────────

resource "aws_api_gateway_method" "event_tenant_post" {
  rest_api_id   = aws_api_gateway_rest_api.ingress.id
  resource_id   = aws_api_gateway_resource.event_tenant.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "event_tenant_post" {
  rest_api_id             = aws_api_gateway_rest_api.ingress.id
  resource_id             = aws_api_gateway_resource.event_tenant.id
  http_method             = aws_api_gateway_method.event_tenant_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.proxy.invoke_arn
}

# ── POST /api/v1/ingress/internal ──────────────────────────────

resource "aws_api_gateway_method" "internal_post" {
  rest_api_id   = aws_api_gateway_rest_api.ingress.id
  resource_id   = aws_api_gateway_resource.internal.id
  http_method   = "POST"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.lambda.id
}

resource "aws_api_gateway_integration" "internal_post" {
  rest_api_id             = aws_api_gateway_rest_api.ingress.id
  resource_id             = aws_api_gateway_resource.internal.id
  http_method             = aws_api_gateway_method.internal_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.proxy.invoke_arn
}

# ── GET /api/v1/hitl/respond ───────────────────────────────

resource "aws_api_gateway_method" "hitl_respond_get" {
  rest_api_id   = aws_api_gateway_rest_api.ingress.id
  resource_id   = aws_api_gateway_resource.hitl_respond.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "hitl_respond_get" {
  rest_api_id             = aws_api_gateway_rest_api.ingress.id
  resource_id             = aws_api_gateway_resource.hitl_respond.id
  http_method             = aws_api_gateway_method.hitl_respond_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.proxy.invoke_arn
}

# ── POST /api/v1/hitl/jira ─────────────────────────────────

resource "aws_api_gateway_method" "hitl_jira_post" {
  rest_api_id   = aws_api_gateway_rest_api.ingress.id
  resource_id   = aws_api_gateway_resource.hitl_jira.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "hitl_jira_post" {
  rest_api_id             = aws_api_gateway_rest_api.ingress.id
  resource_id             = aws_api_gateway_resource.hitl_jira.id
  http_method             = aws_api_gateway_method.hitl_jira_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.proxy.invoke_arn
}

# ── Deployment & Stage ──────────────────────────────────────

resource "aws_api_gateway_deployment" "ingress" {
  rest_api_id = aws_api_gateway_rest_api.ingress.id

  # Force redeployment when API configuration changes
  triggers = {
    redeployment = sha1(jsonencode([
      "force-deploy-1",
      aws_api_gateway_resource.event.id,
      aws_api_gateway_resource.event_tenant.id,
      aws_api_gateway_resource.internal.id,
      aws_api_gateway_resource.hitl.id,
      aws_api_gateway_resource.hitl_respond.id,
      aws_api_gateway_resource.hitl_jira.id,
      aws_api_gateway_method.event_tenant_post.id,
      aws_api_gateway_method.internal_post.id,
      aws_api_gateway_method.hitl_respond_get.id,
      aws_api_gateway_method.hitl_jira_post.id,
      aws_api_gateway_integration.event_tenant_post.id,
      aws_api_gateway_integration.internal_post.id,
      aws_api_gateway_integration.hitl_respond_get.id,
      aws_api_gateway_integration.hitl_jira_post.id,
      aws_api_gateway_authorizer.lambda.id,
      aws_api_gateway_authorizer.lambda.identity_source,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ══════════════════════════════════════════════════════════════
# API GATEWAY ACCOUNT LOGGING ROLE (Required for stage access logs)
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "api_gw_cloudwatch" {
  name = "${var.name_prefix}-api-gw-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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

resource "aws_iam_role_policy_attachment" "api_gw_cloudwatch" {
  role       = aws_iam_role.api_gw_cloudwatch.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "ingress" {
  cloudwatch_role_arn = aws_iam_role.api_gw_cloudwatch.arn
}

# ══════════════════════════════════════════════════════════════
# API GATEWAY REST API DEPLOYMENT
# ══════════════════════════════════════════════════════════════

resource "aws_api_gateway_stage" "v1" {
  deployment_id = aws_api_gateway_deployment.ingress.id
  rest_api_id   = aws_api_gateway_rest_api.ingress.id
  stage_name    = "v1"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      authError      = "$context.authorizer.error"
    })
  }

  tags = var.extra_tags

  depends_on = [
    aws_api_gateway_account.ingress
  ]
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name              = "/aws/apigateway/${var.name_prefix}-ingress"
  retention_in_days = 7

  tags = var.extra_tags
}

# ── Lambda Permissions for API Gateway ──────────────────────

resource "aws_lambda_permission" "api_gw_proxy" {
  statement_id  = "AllowAPIGatewayInvokeProxy"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.ingress.execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gw_authorizer" {
  statement_id  = "AllowAPIGatewayInvokeAuthorizer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.ingress.execution_arn}/authorizers/${aws_api_gateway_authorizer.lambda.id}"
}
