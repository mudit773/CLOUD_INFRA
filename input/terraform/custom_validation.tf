terraform {
  required_version = ">= 1.3.0"

  required_providers {
    acme = {
      source  = "example.com/custom/acme"
      version = "1.2.3"
    }
  }
}

provider "acme" {
  endpoint = "https://example.internal"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "testing"
}

variable "allowed_sources" {
  type    = list(string)
  default = ["10.20.0.0/16"]
}

resource "acme_network" "main" {
  name        = "custom-network"
  environment = var.environment

  tags = {
    Environment = var.environment
    Owner       = "test"
  }
}

resource "acme_firewall" "main" {
  name = "custom-firewall"

  ingress {
    protocol    = "tcp"
    from_port   = 1234
    to_port     = 1234
    sources     = var.allowed_sources
    description = "Internal application traffic"
  }

  egress {
    protocol     = "tcp"
    from_port    = 5678
    to_port      = 5678
    destinations = ["10.30.0.0/16"]
    description  = "Internal outbound traffic"
  }

  depends_on = [
    acme_network.main
  ]
}

data "acme_image" "base" {
  name = "custom-base-image"
}

module "application" {
  source = "./modules/application"

  network_id    = acme_network.main.id
  firewall_id   = acme_firewall.main.id
  environment   = var.environment
}

output "network_id" {
  value       = acme_network.main.id
  description = "ID of the custom network"
}

output "base_image" {
  value = data.acme_image.base.id
}