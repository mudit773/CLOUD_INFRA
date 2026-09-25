resource "aws_lb" "web" {
  name               = "test-alb"
  internal           = false
  load_balancer_type = "application"

  subnets = [
    aws_subnet.public.id
  ]

  security_groups = [
    aws_security_group.web.id
  ]

  tags = {
    Name = "test-alb"
  }
}