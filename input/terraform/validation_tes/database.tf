resource "aws_db_instance" "main" {
  identifier = "terraform-validation-db"

  engine         = "postgres"
  engine_version = "16"

  instance_class = "db.t3.micro"

  allocated_storage = 20

  username = "admin"
  password = var.db_password

  db_name = "testdb"

  storage_encrypted = true

  publicly_accessible = false

  skip_final_snapshot = true

  vpc_security_group_ids = [
    aws_security_group.web.id
  ]

  tags = {
    Name        = "test-database"
    Environment = var.environment
  }
}