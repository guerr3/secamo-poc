# ──────────────────────────────────────────────────────────────
# VPC Module — Custom VPC with fck-nat (t4g.nano)
# ──────────────────────────────────────────────────────────────
#
# Architecture:
#   - 1 public + 1 private subnet per AZ
#   - fck-nat instance in public subnet (replaces NAT Gateway)
#   - Internet Gateway for public subnets
#   - Route table routing 0.0.0.0/0 through fck-nat for private subnets

# ── Data Sources ─────────────────────────────────────────────

data "aws_ami" "fck_nat" {
  most_recent = true
  owners      = ["568608671756"] # fck-nat community AMI owner

  filter {
    name   = "name"
    values = ["fck-nat-al2023-*-arm64-ebs"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}

# ── VPC ──────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-vpc"
  })
}

# ── Internet Gateway ────────────────────────────────────────

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-igw"
  })
}

# ── Public Subnets ───────────────────────────────────────────

resource "aws_subnet" "public" {
  count = length(var.availability_zones)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-public-${var.availability_zones[count.index]}"
    Tier = "public"
  })
}

# ── Private Subnets ──────────────────────────────────────────

resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 100)
  availability_zone = var.availability_zones[count.index]

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-private-${var.availability_zones[count.index]}"
    Tier = "private"
  })
}

# ── Public Route Table ───────────────────────────────────────

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-public-rt"
  })
}

resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ── fck-nat Instance (replaces NAT Gateway) ─────────────────

resource "aws_security_group" "fck_nat" {
  name_prefix = "${var.name_prefix}-fck-nat-"
  description = "Security group for fck-nat instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow all traffic from private subnets"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [for s in aws_subnet.private : s.cidr_block]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-fck-nat-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_network_interface" "fck_nat" {
  subnet_id         = aws_subnet.public[0].id
  security_groups   = [aws_security_group.fck_nat.id]
  source_dest_check = false

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-fck-nat-eni"
  })
}

resource "aws_instance" "fck_nat" {
  ami           = data.aws_ami.fck_nat.id
  instance_type = "t4g.nano"

  network_interface {
    network_interface_id = aws_network_interface.fck_nat.id
    device_index         = 0
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-fck-nat"
  })
}

resource "aws_eip" "fck_nat" {
  domain            = "vpc"
  network_interface = aws_network_interface.fck_nat.id

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-fck-nat-eip"
  })

  depends_on = [aws_internet_gateway.main]
}

# ── Private Route Table (via fck-nat) ───────────────────────

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_network_interface.fck_nat.id
  }

  tags = merge(var.extra_tags, {
    Name = "${var.name_prefix}-private-rt"
  })
}

resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
