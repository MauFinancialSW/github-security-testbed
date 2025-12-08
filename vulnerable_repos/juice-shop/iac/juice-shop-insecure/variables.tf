# Variables for INSECURE Juice Shop deployment
# =============================================
# These variables intentionally have weak defaults for training purposes

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "insecure-demo"
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Environment = "Demo"
    Purpose     = "Security Training"
    # VULNERABILITY: No owner, cost center, or data classification tags
  }
}

# VULNERABILITY: No validation on these variables
variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access resources"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # INSECURE: Allow all
}

variable "enable_https_only" {
  description = "Enforce HTTPS only"
  type        = bool
  default     = false  # INSECURE: HTTP allowed
}

variable "min_tls_version" {
  description = "Minimum TLS version"
  type        = string
  default     = "1.0"  # INSECURE: Should be 1.2
}

variable "backup_retention_days" {
  description = "Database backup retention in days"
  type        = number
  default     = 7  # INSECURE: Should be 35+ for compliance
}

variable "enable_threat_detection" {
  description = "Enable threat detection"
  type        = bool
  default     = false  # INSECURE: Should be true
}

variable "enable_audit_logging" {
  description = "Enable audit logging"
  type        = bool
  default     = false  # INSECURE: Should be true
}
