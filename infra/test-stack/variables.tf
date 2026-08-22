variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "create_test_db" {
  description = "Also create a publicly accessible RDS instance (costs ~Rs 2/hr, takes ~5 min)"
  type        = bool
  default     = false
}

variable "db_password" {
  description = "Master password for the optional test RDS instance"
  type        = string
  default     = "RogueTest123!"
}
