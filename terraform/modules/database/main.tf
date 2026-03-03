# ──────────────────────────────────────────────────────────────
# Database Module — RDS PostgreSQL (db.t4g.small)
# ──────────────────────────────────────────────────────────────

# ── DB Subnet Group ──────────────────────────────────────────

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-db-subnet-group"
  })
}

# ── RDS Instance ─────────────────────────────────────────────

resource "aws_db_instance" "temporal" {
  identifier = "${var.name_prefix}-temporal-db"

  engine         = "postgres"
  engine_version = "16.4"
  instance_class = var.db_instance_class

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  allocated_storage     = 20
  max_allocated_storage = 50
  storage_type          = "gp3"
  storage_encrypted     = true

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [var.db_security_group_id]

  multi_az            = false # Single-AZ for PoC cost savings
  publicly_accessible = false

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  skip_final_snapshot       = true
  final_snapshot_identifier = "${var.name_prefix}-temporal-db-final"
  deletion_protection       = false # Disabled for PoC teardown

  performance_insights_enabled = false # Disabled for cost savings

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-temporal-db"
  })
}
