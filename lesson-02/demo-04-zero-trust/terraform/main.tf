# =============================================================================
# Azure Zero Trust Network Segmentation with Terraform
# =============================================================================
# Course: GitHub Copilot for Cybersecurity Specialists
# Lesson: 02 - Security Protocols with Copilot
#
# Security Features:
# - VNet with segmented subnets (web, app, data)
# - Network Security Groups with explicit allow rules
# - Default deny for all other traffic
# - NSG Flow Logs enabled for audit and compliance
# - Least privilege network access controls
# - Defense in depth with subnet isolation
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

provider "azurerm" {
  features {}
}

# =============================================================================
# Variables
# =============================================================================

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "zerotrust"
}

variable "vnet_address_space" {
  description = "VNet address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "web_subnet_prefix" {
  description = "Web tier subnet address prefix"
  type        = string
  default     = "10.0.1.0/24"
}

variable "app_subnet_prefix" {
  description = "App tier subnet address prefix"
  type        = string
  default     = "10.0.2.0/24"
}

variable "data_subnet_prefix" {
  description = "Data tier subnet address prefix"
  type        = string
  default     = "10.0.3.0/24"
}

variable "log_analytics_retention_days" {
  description = "Number of days to retain NSG flow logs"
  type        = number
  default     = 30
}

# =============================================================================
# Resource Group
# =============================================================================

resource "azurerm_resource_group" "main" {
  name     = "${var.project_name}-${var.environment}-rg"
  location = var.location

  tags = {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
    Purpose     = "zero-trust-network-segmentation"
  }
}

# =============================================================================
# Log Analytics Workspace for NSG Flow Logs
# =============================================================================

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.project_name}-${var.environment}-law"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention_days

  tags = {
    Environment = var.environment
    Purpose     = "nsg-flow-logs-audit"
  }
}

# =============================================================================
# Storage Account for NSG Flow Logs
# =============================================================================

resource "azurerm_storage_account" "flow_logs" {
  name                     = "${var.project_name}${var.environment}flowlogs"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Security: Enable blob encryption
  enable_https_traffic_only = true

  tags = {
    Environment = var.environment
    Purpose     = "nsg-flow-logs-storage"
  }
}

# =============================================================================
# Network Watcher (required for NSG flow logs)
# =============================================================================

resource "azurerm_network_watcher" "main" {
  name                = "${var.project_name}-${var.environment}-nw"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Environment = var.environment
  }
}

# =============================================================================
# Virtual Network - Zero Trust Foundation
# =============================================================================

resource "azurerm_virtual_network" "main" {
  name                = "${var.project_name}-${var.environment}-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = var.vnet_address_space

  tags = {
    Environment = var.environment
    Purpose     = "zero-trust-segmentation"
  }
}

# =============================================================================
# Subnets - Three-Tier Architecture
# =============================================================================

resource "azurerm_subnet" "web" {
  name                 = "web-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.web_subnet_prefix]
}

resource "azurerm_subnet" "app" {
  name                 = "app-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.app_subnet_prefix]
}

resource "azurerm_subnet" "data" {
  name                 = "data-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.data_subnet_prefix]
}

# =============================================================================
# Network Security Group - Web Tier
# =============================================================================

resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Environment = var.environment
    Tier        = "web"
  }
}

# Web NSG Rules - Allow HTTPS from Internet
resource "azurerm_network_security_rule" "web_inbound_https" {
  name                        = "Allow-HTTPS-Inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "Internet"
  destination_address_prefix  = var.web_subnet_prefix
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.web.name
  description                 = "Allow HTTPS traffic from internet to web tier"
}

# Web NSG Rules - Allow outbound to App tier on port 8080
resource "azurerm_network_security_rule" "web_outbound_app" {
  name                        = "Allow-App-Outbound"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8080"
  source_address_prefix       = var.web_subnet_prefix
  destination_address_prefix  = var.app_subnet_prefix
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.web.name
  description                 = "Allow web tier to communicate with app tier"
}

# Web NSG Rules - Deny all other inbound traffic
resource "azurerm_network_security_rule" "web_deny_all_inbound" {
  name                        = "Deny-All-Inbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.web.name
  description                 = "Explicit deny all other inbound traffic"
}

# Web NSG Rules - Deny all other outbound traffic
resource "azurerm_network_security_rule" "web_deny_all_outbound" {
  name                        = "Deny-All-Outbound"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.web.name
  description                 = "Explicit deny all other outbound traffic"
}

# =============================================================================
# Network Security Group - App Tier
# =============================================================================

resource "azurerm_network_security_group" "app" {
  name                = "app-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Environment = var.environment
    Tier        = "app"
  }
}

# App NSG Rules - Allow inbound from Web tier on port 8080
resource "azurerm_network_security_rule" "app_inbound_web" {
  name                        = "Allow-Web-Inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8080"
  source_address_prefix       = var.web_subnet_prefix
  destination_address_prefix  = var.app_subnet_prefix
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
  description                 = "Allow traffic from web tier"
}

# App NSG Rules - Allow outbound to Data tier on port 5432
resource "azurerm_network_security_rule" "app_outbound_data" {
  name                        = "Allow-Data-Outbound"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "5432"
  source_address_prefix       = var.app_subnet_prefix
  destination_address_prefix  = var.data_subnet_prefix
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
  description                 = "Allow app tier to communicate with data tier"
}

# App NSG Rules - Deny all other inbound traffic
resource "azurerm_network_security_rule" "app_deny_all_inbound" {
  name                        = "Deny-All-Inbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
  description                 = "Explicit deny all other inbound traffic"
}

# App NSG Rules - Deny all other outbound traffic
resource "azurerm_network_security_rule" "app_deny_all_outbound" {
  name                        = "Deny-All-Outbound"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.app.name
  description                 = "Explicit deny all other outbound traffic"
}

# =============================================================================
# Network Security Group - Data Tier
# =============================================================================

resource "azurerm_network_security_group" "data" {
  name                = "data-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    Environment = var.environment
    Tier        = "data"
  }
}

# Data NSG Rules - Allow inbound from App tier on port 5432
resource "azurerm_network_security_rule" "data_inbound_app" {
  name                        = "Allow-App-Inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "5432"
  source_address_prefix       = var.app_subnet_prefix
  destination_address_prefix  = var.data_subnet_prefix
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.data.name
  description                 = "Allow PostgreSQL traffic from app tier only"
}

# Data NSG Rules - Deny all other inbound traffic
resource "azurerm_network_security_rule" "data_deny_all_inbound" {
  name                        = "Deny-All-Inbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.data.name
  description                 = "Explicit deny all other inbound traffic"
}

# Data NSG Rules - Deny all outbound traffic (data tier doesn't initiate connections)
resource "azurerm_network_security_rule" "data_deny_all_outbound" {
  name                        = "Deny-All-Outbound"
  priority                    = 4096
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.data.name
  description                 = "Data tier should not initiate outbound connections"
}

# =============================================================================
# Associate NSGs with Subnets
# =============================================================================

resource "azurerm_subnet_network_security_group_association" "web" {
  subnet_id                 = azurerm_subnet.web.id
  network_security_group_id = azurerm_network_security_group.web.id
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

resource "azurerm_subnet_network_security_group_association" "data" {
  subnet_id                 = azurerm_subnet.data.id
  network_security_group_id = azurerm_network_security_group.data.id
}

# =============================================================================
# NSG Flow Logs - Web Tier
# =============================================================================

resource "azurerm_network_watcher_flow_log" "web" {
  name                 = "web-nsg-flow-log"
  network_watcher_name = azurerm_network_watcher.main.name
  resource_group_name  = azurerm_resource_group.main.name

  network_security_group_id = azurerm_network_security_group.web.id
  storage_account_id        = azurerm_storage_account.flow_logs.id
  enabled                   = true
  version                   = 2

  retention_policy {
    enabled = true
    days    = var.log_analytics_retention_days
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }

  tags = {
    Environment = var.environment
    Tier        = "web"
    Purpose     = "security-audit"
  }
}

# =============================================================================
# NSG Flow Logs - App Tier
# =============================================================================

resource "azurerm_network_watcher_flow_log" "app" {
  name                 = "app-nsg-flow-log"
  network_watcher_name = azurerm_network_watcher.main.name
  resource_group_name  = azurerm_resource_group.main.name

  network_security_group_id = azurerm_network_security_group.app.id
  storage_account_id        = azurerm_storage_account.flow_logs.id
  enabled                   = true
  version                   = 2

  retention_policy {
    enabled = true
    days    = var.log_analytics_retention_days
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }

  tags = {
    Environment = var.environment
    Tier        = "app"
    Purpose     = "security-audit"
  }
}

# =============================================================================
# NSG Flow Logs - Data Tier
# =============================================================================

resource "azurerm_network_watcher_flow_log" "data" {
  name                 = "data-nsg-flow-log"
  network_watcher_name = azurerm_network_watcher.main.name
  resource_group_name  = azurerm_resource_group.main.name

  network_security_group_id = azurerm_network_security_group.data.id
  storage_account_id        = azurerm_storage_account.flow_logs.id
  enabled                   = true
  version                   = 2

  retention_policy {
    enabled = true
    days    = var.log_analytics_retention_days
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }

  tags = {
    Environment = var.environment
    Tier        = "data"
    Purpose     = "security-audit"
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "vnet_id" {
  description = "Virtual Network ID"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Virtual Network name"
  value       = azurerm_virtual_network.main.name
}

output "web_subnet_id" {
  description = "Web tier subnet ID"
  value       = azurerm_subnet.web.id
}

output "app_subnet_id" {
  description = "App tier subnet ID"
  value       = azurerm_subnet.app.id
}

output "data_subnet_id" {
  description = "Data tier subnet ID"
  value       = azurerm_subnet.data.id
}

output "web_nsg_id" {
  description = "Web tier Network Security Group ID"
  value       = azurerm_network_security_group.web.id
}

output "app_nsg_id" {
  description = "App tier Network Security Group ID"
  value       = azurerm_network_security_group.app.id
}

output "data_nsg_id" {
  description = "Data tier Network Security Group ID"
  value       = azurerm_network_security_group.data.id
}

output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace ID for NSG flow logs"
  value       = azurerm_log_analytics_workspace.main.id
}

output "flow_logs_storage_account_id" {
  description = "Storage Account ID for NSG flow logs"
  value       = azurerm_storage_account.flow_logs.id
}

output "network_watcher_id" {
  description = "Network Watcher ID"
  value       = azurerm_network_watcher.main.id
}

