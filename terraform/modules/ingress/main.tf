# ──────────────────────────────────────────────────────────────
# Ingress Module — API Gateway (HTTP API) + Lambda
# ──────────────────────────────────────────────────────────────
#
# Routes:  ANY /api/v1/ingress/{proxy+} → Lambda
# Runtime: Python 3.11 (Mangum wrapping FastAPI)

# ── Lambda Function ──────────────────────────────────────────

# Placeholder for the Lambda deployment package.
# In CI/CD, build the package from the ingress-service codebase
# and reference the resulting .zip here.

resource "aws_lambda_function" "ingress" {
  function_name = "${var.name_prefix}-ingress"
  role          = var.lambda_role_arn
  handler       = "handler.handler"
  runtime       = "python3.11"
  memory_size   = var.lambda_memory
  timeout       = var.lambda_timeout
  architectures = ["arm64"]

  # TODO: replace with S3-based deployment in CI/CD
  filename         = "${path.module}/placeholder.zip"
  source_code_hash = filebase64sha256("${path.module}/placeholder.zip")

  environment {
    variables = {
      ENVIRONMENT = "poc"
      LOG_LEVEL   = "INFO"
    }
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-ingress-lambda"
  })

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}

# ── API Gateway (HTTP API) ──────────────────────────────────

resource "aws_apigatewayv2_api" "ingress" {
  name          = "${var.name_prefix}-ingress-api"
  protocol_type = "HTTP"

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-ingress-api"
  })
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.ingress.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
    })
  }

  tags = var.extra_tags
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name              = "/aws/apigateway/${var.name_prefix}-ingress"
  retention_in_days = 7

  tags = var.extra_tags
}

# ── Integration (Lambda proxy) ──────────────────────────────

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.ingress.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.ingress.invoke_arn
  payload_format_version = "2.0"
}

# ── Route: ANY /api/v1/ingress/{proxy+} ─────────────────────

resource "aws_apigatewayv2_route" "ingress_proxy" {
  api_id    = aws_apigatewayv2_api.ingress.id
  route_key = "ANY /api/v1/ingress/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

# ── Lambda Permission for API Gateway ───────────────────────

resource "aws_lambda_permission" "api_gw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingress.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.ingress.execution_arn}/*/*"
}
