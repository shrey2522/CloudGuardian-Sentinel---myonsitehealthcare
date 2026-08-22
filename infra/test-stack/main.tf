##############################################################################
# CloudGuardian Sentinel - "ROGUE STACK" (external misconfiguration test)
#
# Purpose: simulate a developer applying a risky stack that Sentinel did NOT
# create. Apply this, then click "Scan now" on the dashboard (or wait for the
# monitor's next cycle) and watch Sentinel detect resources it has never seen.
#
# Sentinel cannot auto-remediate these (they are not managed by its own
# stack) - findings will be flagged for MANUAL remediation. That is by design.
#
# Cleanup when done:  terraform destroy
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

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  tags = {
    Project = "cloudguardian-sentinel"
    Stack   = "rogue-external-test"
  }
}

# MISCONFIG A: brand-new security group, SSH + MySQL open to the internet
# -> triggers AWS-SG-SSH-OPEN and AWS-SG-DB-PORTS-OPEN
resource "aws_security_group" "rogue_open" {
  name        = "dev-quickfix-${random_id.suffix.hex}"
  description = "temp rule, will fix later (famous last words)"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
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

# MISCONFIG B: publicly readable S3 bucket
# -> triggers AWS-S3-PUBLIC-READ
resource "aws_s3_bucket" "rogue_public" {
  bucket = "dev-shared-dumps-${random_id.suffix.hex}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "off" {
  bucket                  = aws_s3_bucket.rogue_public.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket     = aws_s3_bucket.rogue_public.id
  depends_on = [aws_s3_bucket_public_access_block.off]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.rogue_public.arn}/*"
      }
    ]
  })
}

# MISCONFIG C (optional): a second, publicly accessible RDS instance
# -> triggers AWS-RDS-PUBLIC and AWS-RDS-UNENCRYPTED
# Off by default to save cost/time; enable with:
#   terraform apply -var=create_test_db=true
resource "aws_db_subnet_group" "rogue" {
  count      = var.create_test_db ? 1 : 0
  name       = "dev-db-subnet-${random_id.suffix.hex}"
  subnet_ids = [for s in data.aws_subnets.all.ids : s]
}

data "aws_subnets" "all" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_db_instance" "rogue_public" {
  count                  = var.create_test_db ? 1 : 0
  identifier             = "dev-public-db-${random_id.suffix.hex}"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  storage_encrypted      = false
  db_name                = "devdb"
  username               = "dev"
  password               = var.db_password
  publicly_accessible    = true
  db_subnet_group_name   = aws_db_subnet_group.rogue[0].name
  vpc_security_group_ids = [aws_security_group.rogue_open.id]
  skip_final_snapshot    = true
  apply_immediately      = true
  tags                   = local.tags
}
