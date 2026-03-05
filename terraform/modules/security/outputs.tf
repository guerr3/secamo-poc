# ──────────────────────────────────────────────────────────────
# Security Module — Outputs
# ──────────────────────────────────────────────────────────────

output "worker_security_group_id" {
  description = "Security group ID for worker EC2 instances"
  value       = aws_security_group.worker.id
}

output "db_security_group_id" {
  description = "Security group ID for RDS"
  value       = aws_security_group.database.id
}

output "worker_instance_profile_name" {
  description = "IAM instance profile name for workers"
  value       = aws_iam_instance_profile.worker.name
}

output "worker_role_arn" {
  description = "IAM role ARN for worker EC2 instances"
  value       = aws_iam_role.worker.arn
}

output "ingress_lambda_role_arn" {
  description = "IAM role ARN for the ingress Lambda"
  value       = aws_iam_role.ingress_lambda.arn
}

output "db_password_ssm_parameter_name" {
  description = "SSM parameter name for the DB password"
  value       = aws_ssm_parameter.db_password.name
}

output "lambda_security_group_id" {
  description = "Security group ID for the ingress Proxy Lambda"
  value       = aws_security_group.lambda.id
}

output "authorizer_lambda_role_arn" {
  description = "IAM role ARN for the Authorizer Lambda"
  value       = aws_iam_role.authorizer_lambda.arn
}
