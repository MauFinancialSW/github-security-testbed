# Lesson 02: Implement Security Protocols with Copilot

**Duration:** 40 minutes

## Learning Objectives

- Use Copilot to generate cryptographically correct implementations
- Implement OAuth 2.0 with PKCE using Copilot
- Integrate Azure Key Vault for secure key management
- Generate zero-trust infrastructure with Terraform

## Lab Files

| File | Purpose |
|------|---------|
| `labs/lesson-02/encryption-demo.js` | AES-256-GCM encryption |
| `labs/lesson-02/oauth-server.js` | OAuth 2.0 with PKCE |
| `labs/lesson-02/keyvault-client.js` | Azure Key Vault integration |
| `iac/juice-shop-insecure/` | Vulnerable Terraform baseline |
| `iac/juice-shop-hardened/` | Zero-trust Terraform |

## Setup

```bash
# Azure CLI authentication (for Key Vault demo)
az login

# Terraform initialization (for IaC demo)
cd iac/juice-shop-insecure
terraform init
```

## Demo Flow

### Demo 1: Copilot Security Knowledge (10 min)
- Generate AES-256-GCM encryption
- Show PCI-DSS compliant key derivation
- Validate with GHAS

### Demo 2: Authentication with Copilot (10 min)
- Generate OAuth 2.0 with PKCE
- Create JWT with secure defaults
- Demonstrate secret scanning

### Demo 3: Encryption and Key Management (10 min)
- Integrate Azure Key Vault
- Implement key rotation
- Dependency scanning demo

### Demo 4: Zero-Trust Infrastructure (10 min)
- Generate network segmentation Terraform
- Create service mesh configuration
- GHAS IaC scanning

## Related IaC

The `iac/` directory contains:
- `juice-shop-insecure/` - Deliberately vulnerable deployment
- `juice-shop-hardened/` - Secure baseline with zero-trust controls
