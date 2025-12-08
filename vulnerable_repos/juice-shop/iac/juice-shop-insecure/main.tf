# OWASP Juice Shop - INTENTIONALLY INSECURE Terraform
# =====================================================
# WARNING: This configuration contains deliberate security misconfigurations
# for educational purposes. DO NOT deploy to production.
#
# Vulnerabilities demonstrated:
# - Public IP exposure (no private endpoints)
# - Permissive network security groups (0.0.0.0/0)
# - TLS 1.0/1.1 allowed
# - No encryption at rest
# - No audit logging
# - Hardcoded credentials (CWE-798)
# - SQL database publicly accessible
#
# Used for: MS Press GitHub Copilot for Cybersecurity Professionals
# Lesson 02: Demo 4 - Zero-Trust Infrastructure (starting point)
# Lesson 05: Demo 1 - IaC Security Templates (vulnerable baseline)

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# -----------------------------------------------------------------------------
# VARIABLES - Some with insecure defaults
# -----------------------------------------------------------------------------

variable "resource_group_name" {
  description = "Name of the resource group"
  default     = "rg-juiceshop-insecure"
}

variable "location" {
  description = "Azure region"
  default     = "eastus"
}

# VULNERABILITY: Hardcoded default password (CWE-798)
# checkov:skip=CKV_SECRET_6: Intentionally insecure for training
variable "sql_admin_password" {
  description = "SQL Server admin password"
  default     = "JuiceShop123!"  # INSECURE: Hardcoded weak password
  sensitive   = true
}

variable "container_image" {
  description = "Juice Shop container image"
  default     = "bkimminich/juice-shop:latest"
}

# -----------------------------------------------------------------------------
# RESOURCE GROUP
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "juiceshop" {
  name     = var.resource_group_name
  location = var.location

  # VULNERABILITY: No resource locks
  # VULNERABILITY: No tags for cost/security tracking
}

# -----------------------------------------------------------------------------
# NETWORKING - Intentionally permissive
# -----------------------------------------------------------------------------

resource "azurerm_virtual_network" "juiceshop" {
  name                = "vnet-juiceshop-insecure"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.juiceshop.location
  resource_group_name = azurerm_resource_group.juiceshop.name

  # VULNERABILITY: No DDoS protection plan
  # VULNERABILITY: No network watcher
}

# VULNERABILITY: Single flat subnet (no network segmentation)
resource "azurerm_subnet" "default" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.juiceshop.name
  virtual_network_name = azurerm_virtual_network.juiceshop.name
  address_prefixes     = ["10.0.0.0/24"]

  # VULNERABILITY: No service endpoints
  # VULNERABILITY: No network security group association
}

# VULNERABILITY: Overly permissive NSG allowing all inbound traffic
resource "azurerm_network_security_group" "juiceshop" {
  name                = "nsg-juiceshop-insecure"
  location            = azurerm_resource_group.juiceshop.location
  resource_group_name = azurerm_resource_group.juiceshop.name

  # VULNERABILITY: Allow ALL inbound from internet (CKV_AZURE_9)
  security_rule {
    name                       = "AllowAllInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"  # INSECURE: 0.0.0.0/0
    destination_address_prefix = "*"
  }

  # VULNERABILITY: Allow ALL outbound
  security_rule {
    name                       = "AllowAllOutbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # VULNERABILITY: No NSG flow logs enabled
}

# -----------------------------------------------------------------------------
# SQL DATABASE - Publicly accessible, no encryption
# -----------------------------------------------------------------------------

resource "random_string" "sql_suffix" {
  length  = 8
  special = false
  upper   = false
}

resource "azurerm_mssql_server" "juiceshop" {
  name                         = "sql-juiceshop-${random_string.sql_suffix.result}"
  resource_group_name          = azurerm_resource_group.juiceshop.name
  location                     = azurerm_resource_group.juiceshop.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password

  # VULNERABILITY: No Azure AD authentication (CKV_AZURE_23)
  # VULNERABILITY: Public network access enabled (CKV_AZURE_24)
  public_network_access_enabled = true

  # VULNERABILITY: Minimum TLS version not enforced (CKV_AZURE_28)
  minimum_tls_version = "1.0"  # INSECURE: Should be 1.2

  # VULNERABILITY: No threat detection policy
  # VULNERABILITY: No audit logging
}

# VULNERABILITY: Firewall rule allows ALL Azure services AND internet
resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "AllowAllWindowsAzureIps"
  server_id        = azurerm_mssql_server.juiceshop.id
  start_ip_address = "0.0.0.0"  # INSECURE: Allows all IPs
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_database" "juiceshop" {
  name           = "juiceshop-db"
  server_id      = azurerm_mssql_server.juiceshop.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  max_size_gb    = 2
  sku_name       = "Basic"

  # VULNERABILITY: No transparent data encryption with CMK
  # VULNERABILITY: No threat detection
  # VULNERABILITY: Short backup retention
  short_term_retention_policy {
    retention_days = 7  # INSECURE: Should be 35+ for compliance
  }

  # VULNERABILITY: No long-term retention policy
  # VULNERABILITY: No geo-redundant backup
}

# -----------------------------------------------------------------------------
# STORAGE ACCOUNT - Public access, no encryption
# -----------------------------------------------------------------------------

resource "azurerm_storage_account" "juiceshop" {
  name                     = "stjuiceshop${random_string.sql_suffix.result}"
  resource_group_name      = azurerm_resource_group.juiceshop.name
  location                 = azurerm_resource_group.juiceshop.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # VULNERABILITY: HTTP allowed (CKV_AZURE_3)
  enable_https_traffic_only = false

  # VULNERABILITY: Public blob access enabled (CKV_AZURE_34)
  allow_nested_items_to_be_public = true

  # VULNERABILITY: No blob soft delete
  # VULNERABILITY: No versioning
  # VULNERABILITY: No infrastructure encryption

  # VULNERABILITY: Shared key access enabled (should use Azure AD)
  shared_access_key_enabled = true

  # VULNERABILITY: Minimum TLS version not set (CKV_AZURE_44)
  min_tls_version = "TLS1_0"

  # VULNERABILITY: No network rules (public access)
  # VULNERABILITY: No private endpoints
}

# VULNERABILITY: Public blob container
resource "azurerm_storage_container" "uploads" {
  name                  = "uploads"
  storage_account_name  = azurerm_storage_account.juiceshop.name
  container_access_type = "blob"  # INSECURE: Public read access
}

# -----------------------------------------------------------------------------
# CONTAINER INSTANCE - Juice Shop Application
# -----------------------------------------------------------------------------

resource "azurerm_container_group" "juiceshop" {
  name                = "aci-juiceshop-insecure"
  location            = azurerm_resource_group.juiceshop.location
  resource_group_name = azurerm_resource_group.juiceshop.name
  os_type             = "Linux"
  ip_address_type     = "Public"  # VULNERABILITY: Public IP
  dns_name_label      = "juiceshop-${random_string.sql_suffix.result}"

  container {
    name   = "juiceshop"
    image  = var.container_image
    cpu    = "1"
    memory = "1.5"

    ports {
      port     = 3000
      protocol = "TCP"
    }

    # VULNERABILITY: Sensitive data in environment variables
    environment_variables = {
      NODE_ENV = "production"
    }

    # VULNERABILITY: No resource limits could allow DoS
    # VULNERABILITY: Running as root (default)
    # VULNERABILITY: No health probes
  }

  # VULNERABILITY: No managed identity (using hardcoded credentials)
  # VULNERABILITY: No encryption
  # VULNERABILITY: No diagnostics/logging
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------

output "juiceshop_url" {
  description = "Juice Shop application URL"
  value       = "http://${azurerm_container_group.juiceshop.fqdn}:3000"
}

output "sql_server_fqdn" {
  description = "SQL Server FQDN (publicly accessible!)"
  value       = azurerm_mssql_server.juiceshop.fully_qualified_domain_name
}

# VULNERABILITY: Exposing storage connection string in output
output "storage_connection_string" {
  description = "Storage account connection string (INSECURE: exposed in state)"
  value       = azurerm_storage_account.juiceshop.primary_connection_string
  sensitive   = true
}

output "security_warnings" {
  description = "Security warnings for this deployment"
  value = <<-EOT
    ⚠️  WARNING: This deployment is INTENTIONALLY INSECURE

    Vulnerabilities present:
    - SQL Server publicly accessible with weak password
    - Storage account allows HTTP and public blob access
    - Network security group allows all traffic (0.0.0.0/0)
    - TLS 1.0 allowed on all services
    - No encryption at rest
    - No audit logging
    - No threat detection
    - Hardcoded credentials

    DO NOT use this configuration in production!

    For hardened configuration, see: ../juice-shop-hardened/
  EOT
}
