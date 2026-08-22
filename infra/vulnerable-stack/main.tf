##############################################################################
# CloudGuardian Sentinel - DEMO STACK (variable-driven)
#
# Deploys resources whose security posture is controlled by variables so the
# Sentinel remediator can converge them to a safe state via:
#     terraform apply -var <toggle>=<safe-value>
# and roll back by re-applying the previously recorded values.
#
# Defaults deploy the INTENTIONALLY VULNERABLE state:
#   1. Security group open to 0.0.0.0/0 on SSH (22) and MySQL (3306)
#   2. RDS MySQL publicly_accessible = true (and unencrypted storage)
#   3. S3 bucket with no server-side encryption
#   4. S3 bucket public-read policy with public access block disabled
##############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  tags = {
    Project = "cloudguardian-sentinel"
    Stack   = "vulnerable-demo"
  }
}

# --- MISCONFIG 1: security group, dangerous ports gated by variables --------
resource "aws_security_group" "open_sg" {
  name        = "cg-demo-open-${random_id.suffix.hex}"
  description = "INTENTIONALLY VULNERABLE - open SSH/MySQL to the internet"
  vpc_id      = data.aws_vpc.default.id

  # Rules always exist; remediation swaps the world CIDR for the VPC CIDR.
  # (Keeping the blocks present is required: with zero inline ingress blocks the
  # AWS provider treats ingress as externally managed and never revokes.)
  ingress {
    description = "SSH (toggle: ssh_open)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_open ? "0.0.0.0/0" : data.aws_vpc.default.cidr_block]
  }

  ingress {
    description = "MySQL (toggle: db_port_open)"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [var.db_port_open ? "0.0.0.0/0" : data.aws_vpc.default.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# --- MISCONFIG 2: RDS instance, public access gated by variable -------------
resource "aws_db_subnet_group" "demo" {
  name       = "cg-demo-db-subnet-${random_id.suffix.hex}"
  subnet_ids = data.aws_subnets.default.ids
  tags       = local.tags
}

resource "aws_db_instance" "public_db" {
  identifier             = "cg-demo-public-db"
  engine                 = "mysql"
  instance_class         = var.db_instance_class
  allocated_storage      = 20
  storage_type           = "gp2"
  storage_encrypted      = false
  db_name                = "demodb"
  username               = "sentinel"
  password               = var.db_password
  publicly_accessible    = var.db_publicly_accessible
  db_subnet_group_name   = aws_db_subnet_group.demo.name
  vpc_security_group_ids = [aws_security_group.open_sg.id]
  multi_az               = false
  backup_retention_period = 0
  skip_final_snapshot    = true
  apply_immediately      = true
  tags                   = local.tags
}

# --- MISCONFIG 3: S3 bucket, encryption gated by variable --------------------
resource "aws_s3_bucket" "unencrypted" {
  bucket = "cg-demo-unencrypted-${random_id.suffix.hex}"
  tags   = local.tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  count  = var.s3_encrypted ? 1 : 0
  bucket = aws_s3_bucket.unencrypted.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- MISCONFIG 4: public S3 bucket, public access gated by variable ----------
resource "aws_s3_bucket" "public" {
  bucket = "cg-demo-public-${random_id.suffix.hex}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "public_off" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = var.s3_public ? false : true
  block_public_policy     = var.s3_public ? false : true
  ignore_public_acls      = var.s3_public ? false : true
  restrict_public_buckets = var.s3_public ? false : true
}

resource "aws_s3_bucket_policy" "public_read" {
  count  = var.s3_public ? 1 : 0
  bucket = aws_s3_bucket.public.id
  depends_on = [aws_s3_bucket_public_access_block.public_off]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public.arn}/*"
      }
    ]
  })
}
