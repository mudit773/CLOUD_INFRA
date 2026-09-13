variable "region" {
  type        = string
  description = "AWS deployment region"
  default     = "ap-south-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "test"
}

variable "ami_id" {
  type        = string
  description = "AMI ID for the web server"
  default     = "ami-0123456789abcdef0"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type"
  default     = "t3.micro"
}

variable "db_password" {
  type        = string
  description = "Database password"
  sensitive   = true
}