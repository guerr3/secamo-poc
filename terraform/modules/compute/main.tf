# ──────────────────────────────────────────────────────────────
# Compute Module — EC2 (t3.medium) for Temporal Workers
# ──────────────────────────────────────────────────────────────

# ── Data Sources ─────────────────────────────────────────────

# Fallback to latest Amazon Linux 2023 if no AMI ID is provided
data "aws_ami" "al2023" {
  count       = var.ami_id == "" ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  resolved_ami = var.ami_id != "" ? var.ami_id : data.aws_ami.al2023[0].id
}

# ── EC2 Instance ─────────────────────────────────────────────

resource "aws_instance" "worker" {
  ami                    = local.resolved_ami
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [var.worker_security_group_id]
  iam_instance_profile   = var.instance_profile_name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  user_data = base64encode(templatefile("${path.module}/../../scripts/worker-startup.sh", {
    db_endpoint = var.db_endpoint
    db_name     = var.db_name
    db_username = var.db_username
    environment = "poc"
  }))

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-temporal-worker"
    Role = "temporal-worker"
  })

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}
