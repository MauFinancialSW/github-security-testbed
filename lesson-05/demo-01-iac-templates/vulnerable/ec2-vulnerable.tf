# =============================================================================
# VULNERABLE EC2 Configuration - DO NOT USE IN PRODUCTION
# =============================================================================
# Course: GitHub Copilot for Cybersecurity Specialists
# Lesson: 05 - Compliance, IR, Configuration Management
#
# This template demonstrates common IaC security misconfigurations.
# Use for training and comparison with hardened version.
# =============================================================================

# VULNERABILITY: No provider version pinning
provider "aws" {
  region = "us-east-1"
}

# VULNERABILITY: Default VPC usage
resource "aws_instance" "vulnerable_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # VULNERABILITY: Public IP enabled
  associate_public_ip_address = true

  # VULNERABILITY: No encryption on root volume
  root_block_device {
    volume_size           = 20
    delete_on_termination = true
    encrypted             = false  # INSECURE: Should be true
  }

  # VULNERABILITY: No instance metadata service v2 (IMDSv2)
  metadata_options {
    http_tokens = "optional"  # INSECURE: Should be "required"
  }

  # VULNERABILITY: User data with hardcoded credentials
  user_data = <<-EOF
    #!/bin/bash
    # INSECURE: Hardcoded credentials
    export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    export DATABASE_PASSWORD="admin123"

    # INSECURE: Running as root
    yum install -y httpd
    systemctl start httpd
  EOF

  tags = {
    Name = "vulnerable-server"
  }
}

# VULNERABILITY: Overly permissive security group
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Insecure security group"

  # VULNERABILITY: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # INSECURE: Should be specific IPs
  }

  # VULNERABILITY: All ports open
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # INSECURE: All ports exposed
  }

  # VULNERABILITY: Unrestricted egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULNERABILITY: S3 bucket without encryption or versioning
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "vulnerable-data-bucket-12345"

  tags = {
    Name = "vulnerable-bucket"
  }
}

# VULNERABILITY: Public bucket policy
resource "aws_s3_bucket_policy" "vulnerable_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  # INSECURE: Public read access
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # INSECURE: Anyone can access
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
}

# VULNERABILITY: RDS without encryption
resource "aws_db_instance" "vulnerable_db" {
  identifier           = "vulnerable-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  allocated_storage    = 20

  username = "admin"
  password = "password123"  # INSECURE: Weak password, hardcoded

  # VULNERABILITY: Publicly accessible
  publicly_accessible = true  # INSECURE: Should be false

  # VULNERABILITY: No encryption
  storage_encrypted = false  # INSECURE: Should be true

  # VULNERABILITY: No backup
  backup_retention_period = 0  # INSECURE: Should have backups

  # VULNERABILITY: No deletion protection
  deletion_protection = false

  # VULNERABILITY: Auto minor version upgrade disabled
  auto_minor_version_upgrade = false

  skip_final_snapshot = true
}

# VULNERABILITY: IAM role with overly permissive policy
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# VULNERABILITY: Admin access policy
resource "aws_iam_role_policy" "vulnerable_policy" {
  name = "vulnerable-policy"
  role = aws_iam_role.vulnerable_role.id

  # INSECURE: Full admin access
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"  # INSECURE: Should be least privilege
        Resource = "*"
      }
    ]
  })
}
