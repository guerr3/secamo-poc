# ──────────────────────────────────────────────────────────────
# Storage Module — S3 (evidence) + DynamoDB (audit/approval)
# ──────────────────────────────────────────────────────────────

# ── S3 Bucket — Evidence Storage ─────────────────────────────

resource "aws_s3_bucket" "evidence" {
  bucket = var.evidence_bucket_name != "" ? var.evidence_bucket_name : "${var.name_prefix}-evidence-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-evidence"
  })
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
  }
}

# ── DynamoDB Table — Audit & Approval State ──────────────────

resource "aws_dynamodb_table" "audit" {
  name         = "${var.name_prefix}-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }

  attribute {
    name = "alert_id"
    type = "S"
  }

  global_secondary_index {
    name            = "GSI2-AlertId"
    hash_key        = "alert_id"
    range_key       = "SK"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-audit"
  })
}

# ── DynamoDB Table — Processed Events Dedup ───────────────────

resource "aws_dynamodb_table" "processed_events" {
  name         = "${var.name_prefix}-processed-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-processed-events"
  })
}

# ── Data Sources ─────────────────────────────────────────────

data "aws_caller_identity" "current" {}
