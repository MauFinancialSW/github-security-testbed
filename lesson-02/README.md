# Lesson 02: Security Protocols with Copilot

## Course: GitHub Copilot for Cybersecurity Specialists

---

## Overview

This lesson demonstrates how GitHub Copilot can assist in implementing security protocols correctly. We cover cryptographic operations, OAuth 2.0 with PKCE, key management, and zero trust architecture.

---

## Demos

### Demo 01: Cryptographic Operations
**Location:** `demo-01-crypto/`

**Files:**
- `encryption-demo.js` - AES-256-GCM encryption with secure IV handling

**Key Concepts:**
- Authenticated encryption (GCM mode)
- Secure key derivation (PBKDF2, Argon2)
- Cryptographically secure random generation
- Timing-safe comparisons for HMAC verification

**Copilot Prompt:**
```
Encrypt data using AES-256-GCM with secure IV generation
```

---

### Demo 02: OAuth 2.0 with PKCE
**Location:** `demo-02-oauth/`

**Files:**
- `oauth-server.js` - Complete OAuth 2.0 authorization server
- `jwt-generator.js` - JWT token generation with RS256

**Key Concepts:**
- Authorization Code flow with PKCE (RFC 7636)
- SHA-256 code_challenge verification
- Redirect URI whitelist validation
- Proper JWT claims (iss, sub, aud, exp, iat)
- Token rotation for refresh tokens

**Copilot Prompt:**
```
Create OAuth 2.0 authorization server with PKCE support
```

---

### Demo 03: Key Management
**Location:** `demo-03-key-management/`

**Files:**
- `azure-keyvault.js` - Azure Key Vault integration
- `hashicorp-vault.js` - HashiCorp Vault integration

**Key Concepts:**
- Managed identity authentication (no hardcoded credentials)
- Secret rotation policies
- Transit engine for encryption-as-a-service
- Dynamic database credentials

**Copilot Prompt:**
```
Integrate with Azure Key Vault for secret management
```

---

### Demo 04: Zero Trust Architecture
**Location:** `demo-04-zero-trust/`

**Files:**
- `terraform/main.tf` - AWS VPC with network segmentation
- `istio/service-mesh.yaml` - Istio mTLS and authorization policies

**Key Concepts:**
- Private subnets only (no public internet access)
- VPC endpoints for AWS service access
- Strict mTLS between all services
- Authorization policies with deny-by-default
- Service-to-service identity verification

**Copilot Prompt:**
```
Create Terraform config for zero trust network segmentation
```

---

## Prompts Reference

See the `prompts/` directory for detailed prompt templates:
- `crypto-implementation.md` - Cryptographic operations
- `oauth-jwt.md` - OAuth 2.0 and JWT implementation
- `zero-trust.md` - Zero trust architecture

---

## Prerequisites

```bash
# Install dependencies
npm install jsonwebtoken argon2 node-vault @azure/identity @azure/keyvault-secrets

# For Terraform demos
terraform init

# For Istio demos
kubectl apply -f istio/service-mesh.yaml
```

---

## Running the Demos

### Crypto Demo
```bash
node demo-01-crypto/encryption-demo.js
```

### OAuth Server
```bash
node demo-02-oauth/oauth-server.js
# Server starts on http://localhost:3000
```

### JWT Generator
```bash
node demo-02-oauth/jwt-generator.js
```

### Key Vault Demo
```bash
# Azure - requires Azure CLI login
export AZURE_KEYVAULT_URL="https://your-vault.vault.azure.net"
node demo-03-key-management/azure-keyvault.js

# HashiCorp - requires running Vault instance
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="your-token"
node demo-03-key-management/hashicorp-vault.js
```

---

## Security Best Practices Demonstrated

1. **Algorithm Selection**: Always use authenticated encryption (GCM, not CBC)
2. **Key Derivation**: Use high iteration counts for password-based keys
3. **Token Security**: Short-lived access tokens, rotating refresh tokens
4. **PKCE**: Required for all OAuth clients, not just public ones
5. **Network Segmentation**: Explicit deny rules, least privilege
6. **mTLS**: Encryption and authentication at the transport layer
7. **Secret Management**: No hardcoded credentials, use managed identities

---

## Common Mistakes Copilot Helps Avoid

| Mistake | Copilot's Correct Approach |
|---------|----------------------------|
| Using ECB mode | Suggests GCM or CBC with HMAC |
| Reusing IVs | Generates fresh random IV each time |
| Weak key derivation | Uses 600K+ iterations for PBKDF2 |
| Missing JWT claims | Includes all standard claims |
| Implicit grant flow | Suggests authorization code + PKCE |
| Hardcoded secrets | Suggests Key Vault integration |
| Open security groups | Creates deny-by-default policies |
