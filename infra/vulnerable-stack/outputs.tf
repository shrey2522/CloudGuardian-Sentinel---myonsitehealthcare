output "open_security_group_id" {
  value = aws_security_group.open_sg.id
}

output "public_db_identifier" {
  value = aws_db_instance.public_db.identifier
}

output "public_db_arn" {
  value = aws_db_instance.public_db.arn
}

output "unencrypted_bucket" {
  value = aws_s3_bucket.unencrypted.id
}

output "public_bucket" {
  value = aws_s3_bucket.public.id
}
