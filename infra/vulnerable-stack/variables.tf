variable "region" {
  description = "AWS region for the demo stack"
  type        = string
  default     = "us-east-1"
}

variable "db_instance_class" {
  description = "RDS instance class (t3.micro is free-tier eligible)"
  type        = string
  default     = "db.t3.micro"
}

variable "db_password" {
  description = "Master password for the demo RDS instance (demo only)"
  type        = string
  default     = "SentinelDemo123!"
}
