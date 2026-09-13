resource "test_network_resource" "example" {
  name = "security-test"

  ingress {
    protocol    = "tcp"
    from_port   = 1234
    to_port     = 5678
    sources     = ["10.0.0.0/16"]
    description = "internal ingress"
  }

  egress {
    protocol     = "tcp"
    from_port    = 8000
    to_port      = 9000
    destinations = ["10.1.0.0/16"]
    description  = "internal egress"
  }
}