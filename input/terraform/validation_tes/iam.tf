resource "aws_iam_role" "web_role" {
  name = "test-web-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "ec2.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "test-web-role"
  }
}

resource "aws_iam_role_policy" "web_policy" {
  name = "test-web-policy"
  role = aws_iam_role.web_role.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Action = [
          "s3:GetObject"
        ]

        Resource = "*"
      }
    ]
  })
}