# ──────────────────────────────────────────────────────────────
# Outputs — temporal-test
# ──────────────────────────────────────────────────────────────

output "temporal_server_public_ip" {
  description = "Public IP of the Temporal EC2 instance"
  value       = aws_instance.temporal.public_ip
}

output "temporal_ui_url" {
  description = "Temporal Web UI URL"
  value       = "http://${aws_instance.temporal.public_ip}:8080"
}

output "temporal_grpc_endpoint" {
  description = "Temporal gRPC frontend endpoint (for SDK clients/workers)"
  value       = "${aws_instance.temporal.public_ip}:7233"
}

output "ssh_command" {
  description = "SSH command to connect (requires key_pair_name to be set)"
  value       = var.key_pair_name != "" ? "ssh -i ~/.ssh/${var.key_pair_name}.pem ec2-user@${aws_instance.temporal.public_ip}" : "Use SSM: aws ssm start-session --target ${aws_instance.temporal.id}"
}

output "instance_id" {
  description = "EC2 instance ID (for SSM sessions)"
  value       = aws_instance.temporal.id
}

output "ingress_api_url" {
  description = "REST API Gateway invoke URL for the ingress service"
  value       = module.ingress.api_invoke_url
}

output "hitl_respond_url" {
  description = "Full invoke URL for the HiTL signed-link callback endpoint"
  value       = module.ingress.hitl_respond_url
}

output "hitl_token_table" {
  description = "DynamoDB table name for HiTL approval tokens"
  value       = aws_dynamodb_table.hitl_tokens.name
}
