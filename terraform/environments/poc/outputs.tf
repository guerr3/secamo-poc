# ──────────────────────────────────────────────────────────────
# Outputs — Important Endpoints & IDs
# ──────────────────────────────────────────────────────────────

# ── Networking ───────────────────────────────────────────────

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.vpc.public_subnet_ids
}

# ── Ingress ──────────────────────────────────────────────────

output "api_gateway_endpoint" {
  description = "HTTP API Gateway invoke URL"
  value       = module.ingress.api_endpoint
}

output "ingress_lambda_function_name" {
  description = "Name of the ingress Lambda function"
  value       = module.ingress.lambda_function_name
}

# ── Compute ──────────────────────────────────────────────────

output "worker_instance_id" {
  description = "EC2 instance ID of the Temporal worker"
  value       = module.compute.instance_id
}

output "worker_private_ip" {
  description = "Private IP of the worker instance"
  value       = module.compute.private_ip
}

# ── Database ─────────────────────────────────────────────────

output "db_endpoint" {
  description = "RDS PostgreSQL endpoint (host:port)"
  value       = module.database.db_endpoint
}

output "db_password_ssm_parameter" {
  description = "SSM parameter name containing the DB password"
  value       = module.security.db_password_ssm_parameter_name
  sensitive   = true
}

# ── Storage ──────────────────────────────────────────────────

output "evidence_bucket_name" {
  description = "Name of the S3 evidence bucket"
  value       = module.storage.evidence_bucket_name
}

output "audit_table_name" {
  description = "Name of the DynamoDB audit table"
  value       = module.storage.audit_table_name
}
