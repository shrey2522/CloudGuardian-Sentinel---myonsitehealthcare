output "rogue_security_group_id" {
  value = aws_security_group.rogue_open.id
}

output "rogue_public_bucket" {
  value = aws_s3_bucket.rogue_public.id
}
