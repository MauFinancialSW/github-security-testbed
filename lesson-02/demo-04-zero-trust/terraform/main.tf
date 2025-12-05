# =============================================================================
# Zero Trust Network Segmentation with Terraform
# =============================================================================
# Course: GitHub Copilot for Cybersecurity Specialists
# Lesson: 02 - Security Protocols with Copilot
#
# Copilot Prompt Used:
# "Create Terraform config for zero trust network segmentation"
#
# Security Features:
# - VPC with private subnets only (no public internet access)
# - Network ACLs with explicit deny rules
# - Security groups following least privilege
# - VPC endpoints for AWS service access
# - Flow logs for traffic analysis
# =============================================================================

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "zero-trust-demo"
      ManagedBy   = "terraform"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

# =============================================================================
# VPC - Zero Trust Network Foundation
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "zero-trust-vpc"
  }
}

# =============================================================================
# Private Subnets Only (No Public Subnets)
# =============================================================================

resource "aws_subnet" "private_app" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # Zero Trust: No public IPs
  map_public_ip_on_launch = false

  tags = {
    Name = "private-app-${count.index + 1}"
    Tier = "application"
  }
}

resource "aws_subnet" "private_db" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = false

  tags = {
    Name = "private-db-${count.index + 1}"
    Tier = "database"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# =============================================================================
# Network ACLs - Defense in Depth
# =============================================================================

resource "aws_network_acl" "app_tier" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private_app[*].id

  # Inbound: Allow only from approved sources
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 8080
    to_port    = 8080
  }

  # Allow ephemeral ports for responses
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Explicit deny all other inbound
  ingress {
    protocol   = -1
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Outbound: Allow only to specific destinations
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 10)  # DB subnet 1
    from_port  = 5432
    to_port    = 5432
  }

  egress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 11)  # DB subnet 2
    from_port  = 5432
    to_port    = 5432
  }

  egress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 12)  # DB subnet 3
    from_port  = 5432
    to_port    = 5432
  }

  # Allow HTTPS outbound for AWS services via endpoints
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Explicit deny all other outbound
  egress {
    protocol   = -1
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "app-tier-nacl"
  }
}

resource "aws_network_acl" "db_tier" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private_db[*].id

  # Inbound: Only from app tier on PostgreSQL port
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 0)  # App subnet 1
    from_port  = 5432
    to_port    = 5432
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 1)  # App subnet 2
    from_port  = 5432
    to_port    = 5432
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 2)  # App subnet 3
    from_port  = 5432
    to_port    = 5432
  }

  # Explicit deny all other inbound
  ingress {
    protocol   = -1
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Outbound: Only responses to app tier
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 0)
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 1)
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = cidrsubnet(var.vpc_cidr, 8, 2)
    from_port  = 1024
    to_port    = 65535
  }

  # Explicit deny all other outbound
  egress {
    protocol   = -1
    rule_no    = 32766
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "db-tier-nacl"
  }
}

# =============================================================================
# Security Groups - Micro-segmentation
# =============================================================================

resource "aws_security_group" "app" {
  name        = "app-tier-sg"
  description = "Security group for application tier"
  vpc_id      = aws_vpc.main.id

  # No ingress rules - will be added by specific service security groups
  # This follows zero trust: deny by default

  egress {
    description     = "Allow PostgreSQL to database tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.db.id]
  }

  egress {
    description = "Allow HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VPC endpoints
  }

  tags = {
    Name = "app-tier-sg"
  }
}

resource "aws_security_group" "db" {
  name        = "db-tier-sg"
  description = "Security group for database tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow PostgreSQL from app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  # No egress - databases don't initiate connections
  # Exception: If needed for replication, add specific rules

  tags = {
    Name = "db-tier-sg"
  }
}

# =============================================================================
# VPC Endpoints - Private Access to AWS Services
# =============================================================================

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3Access"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:sourceVpc" = aws_vpc.main.id
          }
        }
      }
    ]
  })

  tags = {
    Name = "s3-endpoint"
  }
}

resource "aws_vpc_endpoint" "secrets_manager" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private_app[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "secrets-manager-endpoint"
  }
}

resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private_app[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "kms-endpoint"
  }
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "vpc-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "vpc-endpoints-sg"
  }
}

# =============================================================================
# Route Table - No Internet Gateway
# =============================================================================

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # No route to internet gateway (zero trust)
  # Only routes to VPC endpoints and local

  tags = {
    Name = "private-rt"
  }
}

resource "aws_route_table_association" "app" {
  count          = 3
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "db" {
  count          = 3
  subnet_id      = aws_subnet.private_db[count.index].id
  route_table_id = aws_route_table.private.id
}

# =============================================================================
# VPC Flow Logs - Traffic Monitoring
# =============================================================================

resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = {
    Name = "vpc-flow-logs"
  }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs/${aws_vpc.main.id}"
  retention_in_days = 90

  tags = {
    Name = "vpc-flow-logs"
  }
}

resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# Outputs
# =============================================================================

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_app_subnet_ids" {
  description = "Application tier subnet IDs"
  value       = aws_subnet.private_app[*].id
}

output "private_db_subnet_ids" {
  description = "Database tier subnet IDs"
  value       = aws_subnet.private_db[*].id
}

output "app_security_group_id" {
  description = "Application tier security group ID"
  value       = aws_security_group.app.id
}

output "db_security_group_id" {
  description = "Database tier security group ID"
  value       = aws_security_group.db.id
}
