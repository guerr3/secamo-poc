# ──────────────────────────────────────────────────────────────
# Storage Module — Outputs
# ──────────────────────────────────────────────────────────────

output "evidence_bucket_name" {
  description = "Name of the S3 evidence bucket"
  value       = aws_s3_bucket.evidence.id
}

output "evidence_bucket_arn" {
  description = "ARN of the S3 evidence bucket"
  value       = aws_s3_bucket.evidence.arn
}

output "audit_table_name" {
  description = "Name of the DynamoDB audit table"
  value       = aws_dynamodb_table.audit.name
}

output "audit_table_arn" {
  description = "ARN of the DynamoDB audit table"
  value       = aws_dynamodb_table.audit.arn
}
