# ──────────────────────────────────────────────────────────────
# Compute Module — Outputs
# ──────────────────────────────────────────────────────────────

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.worker.id
}

output "private_ip" {
  description = "Private IP address of the worker"
  value       = aws_instance.worker.private_ip
}
