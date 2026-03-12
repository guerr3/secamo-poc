# ──────────────────────────────────────────────────────────────
# Ingress Module — Outputs
# ──────────────────────────────────────────────────────────────

output "api_invoke_url" {
  description = "REST API Gateway invoke URL (stage v1)"
  value       = aws_api_gateway_stage.v1.invoke_url
}

output "api_id" {
  description = "ID of the REST API Gateway"
  value       = aws_api_gateway_rest_api.ingress.id
}

output "hitl_respond_url" {
  description = "Full invoke URL for the HiTL signed-link callback endpoint"
  value       = "${aws_api_gateway_stage.v1.invoke_url}/api/v1/hitl/respond"
}

output "proxy_lambda_function_name" {
  description = "Name of the Proxy Lambda function"
  value       = aws_lambda_function.proxy.function_name
}

output "proxy_lambda_function_arn" {
  description = "ARN of the Proxy Lambda function"
  value       = aws_lambda_function.proxy.arn
}

output "authorizer_lambda_function_name" {
  description = "Name of the Authorizer Lambda function"
  value       = aws_lambda_function.authorizer.function_name
}
