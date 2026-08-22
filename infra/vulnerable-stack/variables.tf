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

# --- security posture toggles (remediation targets) --------------------------
variable "ssh_open" {
  description = "Allow 0.0.0.0/0 ingress on port 22 (vulnerable when true)"
  type        = bool
  default     = true
}

variable "db_port_open" {
  description = "Allow 0.0.0.0/0 ingress on port 3306 (vulnerable when true)"
  type        = bool
  default     = true
}

variable "db_publicly_accessible" {
  description = "RDS public accessibility (vulnerable when true)"
  type        = bool
  default     = true
}

variable "s3_encrypted" {
  description = "Enable SSE on the demo bucket (vulnerable when false)"
  type        = bool
  default     = false
}

variable "s3_public" {
  description = "Allow public read policy on the demo bucket (vulnerable when true)"
  type        = bool
  default     = true
}
