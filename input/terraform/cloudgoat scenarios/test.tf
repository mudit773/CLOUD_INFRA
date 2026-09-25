terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.116.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.1.0"
    }
  }
}

# ------------------------------------------------
# PROVIDERS
# ------------------------------------------------

provider "azurerm" {
  features {}

  subscription_id = var.subscription_id
}

provider "azurerm" {
  alias           = "secondary"
  subscription_id = var.subscription_id

  features {}
}

provider "random" {}

# ------------------------------------------------
# VARIABLES
# ------------------------------------------------

variable "subscription_id" {
  type        = string
  description = "Azure subscription ID"
  sensitive   = true
}

variable "location" {
  type        = string
  default     = "westus"
  description = "Azure region"

  validation {
    condition     = contains(["westus", "eastus"], var.location)
    error_message = "Location must be westus or eastus."
  }
}

variable "resource_group_name" {
  type        = string
  default     = "security-test-rg"
  description = "Resource group name"
}

variable "allowed_ip" {
  type        = string
  default     = "0.0.0.0/0"
  description = "Allowed source IP"
}

variable "admin_password" {
  type        = string
  sensitive   = true
  description = "Administrator password"
}

variable "allowed_ports" {
  type        = list(number)
  default     = [22, 80, 443]
  description = "Allowed inbound ports"
}

# ------------------------------------------------
# DATA SOURCE
# ------------------------------------------------

data "azurerm_resource_group" "existing" {
  name = var.resource_group_name
}

# ------------------------------------------------
# RANDOM RESOURCE
# ------------------------------------------------

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# ------------------------------------------------
# RESOURCE GROUP
# ------------------------------------------------

resource "azurerm_resource_group" "test" {
  name     = "${var.resource_group_name}-${random_string.suffix.result}"
  location = var.location

  tags = {
    environment = "test"
    purpose     = "security-analysis"
  }
}

# ------------------------------------------------
# NETWORK SECURITY GROUP
# ------------------------------------------------

resource "azurerm_network_security_group" "test" {
  name                = "test-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.test.name

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_ip
    destination_address_prefix = "*"
    description                = "SSH access"
  }

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                  = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    description                = "HTTP access"
  }

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                  = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    description                = "HTTPS access"
  }
}

# ------------------------------------------------
# STORAGE ACCOUNT
# ------------------------------------------------

resource "azurerm_storage_account" "test" {
  name                     = "securitytest${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  public_network_access_enabled = true

  min_tls_version = "TLS1_2"

  blob_properties {
    versioning_enabled = true
  }

  tags = {
    environment = "test"
  }

  depends_on = [
    azurerm_network_security_group.test
  ]
}

# ------------------------------------------------
# KEY VAULT
# ------------------------------------------------

resource "azurerm_key_vault" "test" {
  name                = "security-test-kv-${random_string.suffix.result}"
  location            = var.location
  resource_group_name = azurerm_resource_group.test.name

  tenant_id = "00000000-0000-0000-0000-000000000000"

  sku_name = "standard"

  public_network_access_enabled = true

  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = {
    environment = "test"
  }
}

# ------------------------------------------------
# SECRET
# ------------------------------------------------

resource "azurerm_key_vault_secret" "admin_password" {
  name         = "admin-password"
  value        = var.admin_password
  key_vault_id = azurerm_key_vault.test.id

  depends_on = [
    azurerm_key_vault.test
  ]
}

# ------------------------------------------------
# RESOURCE WITH ENCRYPTION
# ------------------------------------------------

resource "azurerm_storage_account" "encrypted" {
  name                     = "encrypted${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = var.location
  account_tier              = "Standard"
  account_replication_type = "GRS"

  public_network_access_enabled = false

  min_tls_version = "TLS1_2"

  infrastructure_encryption_enabled = true

  tags = {
    encrypted   = "true"
    environment = "test"
  }
}

# ------------------------------------------------
# SECONDARY PROVIDER RESOURCE
# ------------------------------------------------

resource "azurerm_resource_group" "secondary" {
  provider = azurerm.secondary

  name     = "secondary-test-rg"
  location = var.location
}

# ------------------------------------------------
# MODULE
# ------------------------------------------------

module "test_module" {
  source  = "Azure/storage/azurerm"
  version = "1.0.0"

  resource_group_name = azurerm_resource_group.test.name
  location            = var.location

  depends_on = [
    azurerm_resource_group.test
  ]
}

# ------------------------------------------------
# OUTPUTS
# ------------------------------------------------

output "resource_group_id" {
  value       = azurerm_resource_group.test.id
  description = "Test resource group ID"
}

output "storage_account_name" {
  value       = azurerm_storage_account.test.name
  description = "Test storage account name"
}

output "secret_reference" {
  value     = azurerm_key_vault_secret.admin_password.id
  sensitive = true
}

output "existing_resource_group" {
  value = data.azurerm_resource_group.existing.id
}