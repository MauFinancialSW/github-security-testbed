# Juice Shop - Hardened Terraform Deployment

This configuration deploys OWASP Juice Shop to Azure with **security best practices** following CIS Azure Benchmark and zero-trust principles.

## Security Controls Implemented

### Network Security
| Control | Implementation | CIS Reference |
|---------|---------------|---------------|
| No public IPs | Private endpoints only | CIS 6.1 |
| Network segmentation | Web/App/Data subnets | CIS 6.4 |
| Least privilege NSGs | Explicit allow rules only | CIS 6.2 |
| NSG flow logs | Log Analytics integration | CIS 5.1.6 |

### Data Protection
| Control | Implementation | CIS Reference |
|---------|---------------|---------------|
| TLS 1.2+ | Enforced on all services | CIS 4.1.1 |
| Encryption at rest | TDE with CMK | CIS 4.1.3 |
| No public blob access | Private containers | CIS 3.7 |
| Geo-redundant storage | GRS replication | CIS 3.3 |

### Identity & Access
| Control | Implementation | CIS Reference |
|---------|---------------|---------------|
| Azure AD auth | SQL AD-only authentication | CIS 4.1.4 |
| Managed identities | No hardcoded credentials | CIS 1.3 |
| RBAC | Key Vault authorization | CIS 8.5 |
| No shared keys | Storage Azure AD auth | CIS 3.8 |

### Monitoring & Compliance
| Control | Implementation | CIS Reference |
|---------|---------------|---------------|
| SQL audit logging | To storage + Log Analytics | CIS 4.2.1 |
| Threat detection | Enabled on SQL | CIS 4.2.2 |
| Centralized logging | Log Analytics workspace | CIS 5.1.1 |
| Long retention | 90-day minimum | CIS 5.1.2 |

## Usage

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Deploy
terraform apply

# Validate security with checkov
checkov -f main.tf --framework terraform
# Expected: All checks PASSED
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Azure Virtual Network                     │
│                       10.0.0.0/16                           │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Web Tier  │───▶│  App Tier   │───▶│  Data Tier  │     │
│  │ 10.0.1.0/24 │    │ 10.0.2.0/24 │    │ 10.0.3.0/24 │     │
│  │             │    │             │    │             │     │
│  │ ┌─────────┐ │    │             │    │ ┌─────────┐ │     │
│  │ │Container│ │    │             │    │ │SQL (PE) │ │     │
│  │ │Instance │ │    │             │    │ └─────────┘ │     │
│  │ └─────────┘ │    │             │    │             │     │
│  │    NSG-Web  │    │   NSG-App   │    │  NSG-Data   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  Key Vault  │    │   Storage   │    │Log Analytics│     │
│  │   (RBAC)    │    │  (Private)  │    │  Workspace  │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Comparison with Insecure Version

| Control | Insecure | Hardened |
|---------|----------|----------|
| Public IP | Yes | No (Private Endpoint) |
| TLS Version | 1.0 | 1.2+ only |
| Encryption | None | TDE + CMK |
| Firewall | 0.0.0.0/0 | Allowlist only |
| Authentication | SQL Auth | Azure AD only |
| Audit Logs | Disabled | Enabled |
| Threat Detection | Disabled | Enabled |
| Network Segmentation | None | 3-tier |

## Course Integration

This configuration is referenced in:
- `demos/lesson-02-demo-runbook-final.md` - Demo 4 (target state)
- `demos/lesson-05-demo-runbook-final.md` - Demo 1 (hardened baseline)
- `labs/lesson-02/README.md`
- `labs/lesson-05/README.md`

## Compliance Validation

```bash
# CIS Azure Benchmark
checkov -f main.tf --check CKV_AZURE

# Azure Security Benchmark
az policy state list --resource-group rg-juiceshop-hardened

# Custom security policies
terrascan scan -i terraform -p azure
```
