output "vpc_id" {
  description = "ID of the test VPC"
  value       = aws_vpc.main.id
}

output "web_instance_id" {
  description = "ID of the web EC2 instance"
  value       = aws_instance.web.id
}

output "account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "db_endpoint" {
  description = "Database endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}