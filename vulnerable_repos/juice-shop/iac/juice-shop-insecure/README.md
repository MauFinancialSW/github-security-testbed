# Juice Shop - Insecure Terraform Deployment

> **WARNING**: This configuration is INTENTIONALLY INSECURE for educational purposes.
> DO NOT deploy to production environments.

## Purpose

This Terraform configuration deploys OWASP Juice Shop to Azure with deliberate security misconfigurations. It serves as the starting point for:

- **Lesson 02, Demo 4**: Zero-Trust Infrastructure - Shows what NOT to do
- **Lesson 05, Demo 1**: IaC Security Templates - Baseline for hardening comparison

## Vulnerabilities Demonstrated

| Category | Vulnerability | CIS Control | Severity |
|----------|--------------|-------------|----------|
| Network | NSG allows 0.0.0.0/0 inbound | CIS 6.1 | Critical |
| Network | No network segmentation | CIS 6.4 | High |
| Network | No DDoS protection | CIS 6.6 | Medium |
| Database | Public network access | CIS 4.1.2 | Critical |
| Database | TLS 1.0 allowed | CIS 4.1.1 | High |
| Database | No TDE with CMK | CIS 4.1.3 | High |
| Database | Weak admin password | CIS 4.1.4 | Critical |
| Database | No threat detection | CIS 4.2.1 | High |
| Storage | HTTP allowed | CIS 3.1 | High |
| Storage | Public blob access | CIS 3.7 | High |
| Storage | Shared key access | CIS 3.8 | Medium |
| Identity | No managed identity | CIS 1.3 | High |
| Identity | Hardcoded credentials | CWE-798 | Critical |
| Logging | No audit logs | CIS 5.1.1 | High |
| Logging | No NSG flow logs | CIS 5.1.6 | Medium |

## Usage

```bash
# Initialize Terraform
terraform init

# Review the plan (observe all the security issues)
terraform plan

# Deploy (for demo purposes only!)
terraform apply

# IMPORTANT: Destroy when done
terraform destroy
```

## Scanning with Security Tools

### Checkov
```bash
checkov -f main.tf --framework terraform
# Expected: 15+ failed checks
```

### tfsec
```bash
tfsec .
# Expected: Multiple HIGH and CRITICAL findings
```

### Terrascan
```bash
terrascan scan -i terraform
# Expected: CIS Azure benchmark violations
```

## Comparison with Hardened Version

See `../juice-shop-hardened/` for the secure configuration with:
- Private endpoints (no public IPs)
- Network segmentation (web/app/data tiers)
- TLS 1.2+ enforcement
- Encryption at rest with CMK
- Azure AD authentication
- Comprehensive audit logging
- Threat detection enabled
- Managed identities (no hardcoded secrets)

## Course Integration

This configuration is referenced in:
- `demos/lesson-02-demo-runbook-final.md` - Demo 4
- `demos/lesson-05-demo-runbook-final.md` - Demo 1
- `labs/lesson-02/README.md`
- `labs/lesson-05/README.md`
