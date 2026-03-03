# ──────────────────────────────────────────────────────────────
# Ingress Module — Outputs
# ──────────────────────────────────────────────────────────────

output "api_endpoint" {
  description = "HTTP API Gateway invoke URL"
  value       = aws_apigatewayv2_api.ingress.api_endpoint
}

output "api_id" {
  description = "ID of the HTTP API Gateway"
  value       = aws_apigatewayv2_api.ingress.id
}

output "lambda_function_name" {
  description = "Name of the ingress Lambda function"
  value       = aws_lambda_function.ingress.function_name
}

output "lambda_function_arn" {
  description = "ARN of the ingress Lambda function"
  value       = aws_lambda_function.ingress.arn
}
