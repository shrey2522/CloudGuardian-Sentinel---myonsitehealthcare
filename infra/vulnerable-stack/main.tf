##############################################################################
# CloudGuardian Sentinel - INTENTIONALLY VULNERABLE DEMO STACK
#
# This stack deliberately deploys misconfigured resources so the Sentinel
# monitor has something to detect and remediate. NEVER use in production.
#
# Misconfigurations planted:
#   1. Security group open to 0.0.0.0/0 on SSH (22) and MySQL (3306)
#   2. RDS MySQL instance marked publicly_accessible = true  (+ storage unencrypted)
#   3. S3 bucket with no server-side encryption
#   4. S3 bucket with public-read bucket policy and public access block disabled
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

# --- MISCONFIG 1: security group wide open on SSH + MySQL ------------------
resource "aws_security_group" "open_sg" {
  name        = "cg-demo-open-${random_id.suffix.hex}"
  description = "INTENTIONALLY VULNERABLE - open SSH/MySQL to the internet"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH open to world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "MySQL open to world"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

# --- MISCONFIG 2: publicly accessible (and unencrypted) RDS instance -------
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
  publicly_accessible    = true
  db_subnet_group_name   = aws_db_subnet_group.demo.name
  vpc_security_group_ids = [aws_security_group.open_sg.id]
  multi_az               = false
  backup_retention_period = 0
  skip_final_snapshot    = true
  apply_immediately      = true
  tags                   = local.tags
}

# --- MISCONFIG 3: S3 bucket without server-side encryption ------------------
resource "aws_s3_bucket" "unencrypted" {
  bucket = "cg-demo-unencrypted-${random_id.suffix.hex}"
  tags   = local.tags
}

# --- MISCONFIG 4: publicly readable S3 bucket -------------------------------
resource "aws_s3_bucket" "public" {
  bucket = "cg-demo-public-${random_id.suffix.hex}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "public_off" {
  bucket                  = aws_s3_bucket.public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
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
