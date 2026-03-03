# ──────────────────────────────────────────────────────────────
# Database Module — Outputs
# ──────────────────────────────────────────────────────────────

output "db_endpoint" {
  description = "RDS endpoint (host:port)"
  value       = aws_db_instance.temporal.endpoint
}

output "db_address" {
  description = "RDS hostname (without port)"
  value       = aws_db_instance.temporal.address
}

output "db_port" {
  description = "RDS port"
  value       = aws_db_instance.temporal.port
}

output "db_name" {
  description = "Name of the database"
  value       = aws_db_instance.temporal.db_name
}
