
    resource "aws_vpc" "custom_vpc" {
      cidr_block = "10.0.0.0/16"
      tags = {
        Name = "custom-test-vpc"
      }
    }

    resource "aws_security_group" "custom_sg" {
      name   = "custom_sg"
      vpc_id = aws_vpc.custom_vpc.id

      ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
    