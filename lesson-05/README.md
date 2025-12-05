# Lesson 05: Compliance, Incident Response, Configuration Management

## Course: GitHub Copilot for Cybersecurity Specialists

---

## Overview

This lesson covers compliance automation, incident response playbooks, and secure infrastructure configuration. Learn how to use Copilot to generate compliant IaC templates, STIG remediation scripts, and incident response automation.

---

## Demos

### Demo 01: IaC Templates (Vulnerable vs Hardened)
**Location:** `demo-01-iac-templates/`

**Files:**
- `vulnerable/ec2-vulnerable.tf` - Common security misconfigurations
- `hardened/ec2-hardened.tf` - CIS-compliant Terraform configuration

**Security Comparison:**

| Feature | Vulnerable | Hardened |
|---------|-----------|----------|
| Public IP | Yes | No (private subnet) |
| Root Volume Encryption | No | Yes (KMS) |
| IMDSv2 | Optional | Required |
| Security Groups | All ports open | Least privilege |
| IAM Role | Admin access | Least privilege |
| S3 Bucket | Public | Private, encrypted, versioned |
| User Data | Hardcoded secrets | Secrets Manager |

**Copilot Prompt:**
```
Create secure Terraform configuration for EC2 with CIS benchmarks
```

---

### Demo 02: CIS Benchmark Compliance Checker
**Location:** `demo-02-compliance-scripts/`

**Files:**
- `cis-benchmark-checker.js` - AWS CIS Foundations Benchmark 1.4 checker

**Checks Implemented:**
- 1.1: Root account usage
- 1.2: Root MFA enabled
- 1.4: Access key rotation (90 days)
- 1.5: Password policy compliance
- 2.1.1: S3 encryption at rest
- 2.1.2: S3 deny HTTP requests
- 3.1: CloudTrail enabled all regions
- 3.3: CloudTrail KMS encryption
- 4.3: Root usage alerting
- 5.1: NACL admin port restrictions
- 5.3: Default security group restrictions

**Run:**
```bash
node demo-02-compliance-scripts/cis-benchmark-checker.js
```

---

### Demo 03: STIG Remediation
**Location:** `demo-03-stig-remediation/`

**Files:**
- `stig-remediation.sh` - RHEL/Amazon Linux STIG auto-remediation

**STIG Controls Implemented:**
- V-230221: Disable SSH root login
- V-230222: SSH Protocol 2
- V-230223: SSH idle timeout
- V-230234: Password complexity
- V-230235: Password history
- V-230240: Account lockout
- V-230250: Audit configuration
- V-230260: File permissions
- V-230270: Disable USB storage
- V-230280: Enable FIPS mode
- V-230290: Disable CTRL-ALT-DEL
- V-230300: Login banner
- V-230310: NTP configuration

**Run:**
```bash
sudo ./demo-03-stig-remediation/stig-remediation.sh
```

---

### Demo 04: Incident Response Playbooks
**Location:** `demo-04-ir-playbooks/`

**Files:**
- `incident-response.js` - Automated IR playbook framework

**Incident Types:**
- `compromised-instance` - EC2 compromise response
- `unauthorized-access` - Unauthorized access handling
- `data-exfiltration` - Data exfiltration response
- `malware-detected` - Malware incident handling
- `suspicious-api-activity` - API activity investigation

**Response Phases:**
1. **Detect**: Collect instance info, user activity
2. **Contain**: Isolate instance, disable access keys
3. **Collect**: Forensic snapshots, logs, memory dump
4. **Notify**: Slack, PagerDuty alerts
5. **Escalate**: Executive notification for critical

**Run:**
```bash
node demo-04-ir-playbooks/incident-response.js
```

---

## Compliance Frameworks Covered

### CIS AWS Foundations Benchmark 1.4
- Identity and Access Management
- Storage (S3, EBS)
- Logging (CloudTrail, CloudWatch)
- Monitoring (Alarms, Metrics)
- Networking (VPC, Security Groups, NACLs)

### DISA STIG
- RHEL 8 Security Technical Implementation Guide
- Operating system hardening
- Authentication and access control
- Audit logging

### NIST 800-53
- Access Control (AC)
- Audit and Accountability (AU)
- Security Assessment (CA)
- Configuration Management (CM)
- Identification and Authentication (IA)
- Incident Response (IR)
- System and Communications Protection (SC)

---

## IaC Security Best Practices

### Provider Configuration
```hcl
terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
```

### Encryption at Rest
```hcl
root_block_device {
  encrypted  = true
  kms_key_id = aws_kms_key.app_key.arn
}
```

### IMDSv2 Required
```hcl
metadata_options {
  http_tokens = "required"
  http_put_response_hop_limit = 1
}
```

### Least Privilege IAM
```hcl
policy = jsonencode({
  Statement = [
    {
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["${aws_s3_bucket.app.arn}/*"]
    }
  ]
})
```

---

## Incident Response Workflow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   DETECT    │────▶│   CONTAIN   │────▶│   COLLECT   │
│             │     │             │     │             │
│ • Instance  │     │ • Isolate   │     │ • Snapshots │
│ • CloudTrail│     │ • Disable   │     │ • Logs      │
│ • GuardDuty │     │   keys      │     │ • Memory    │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  ESCALATE   │◀────│   NOTIFY    │◀────│  PRESERVE   │
│             │     │             │     │             │
│ • Executive │     │ • Slack     │     │ • S3        │
│ • Legal     │     │ • PagerDuty │     │ • Hash      │
│ • External  │     │ • Email     │     │ • Chain of  │
└─────────────┘     └─────────────┘     │   Custody   │
                                        └─────────────┘
```

---

## Environment Variables

```bash
# AWS Configuration
export AWS_REGION=us-east-1
export AWS_PROFILE=security

# Evidence Storage
export EVIDENCE_BUCKET=security-evidence-bucket

# Notifications
export SLACK_WEBHOOK=https://hooks.slack.com/...
export PAGERDUTY_KEY=...

# Containment
export QUARANTINE_SG=sg-xxxxx
export FORENSICS_SUBNET=subnet-xxxxx
```

---

## Prompts Reference

### IaC Security
```
Create Terraform configuration with CIS benchmark compliance
```

### Compliance Checking
```
Create CIS benchmark compliance checker for AWS resources
```

### STIG Remediation
```
Create STIG remediation script for Linux hardening
```

### Incident Response
```
Create incident response automation playbook for security events
```
