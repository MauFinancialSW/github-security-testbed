# Lesson 02 Lab Files - Testing Guide

## Files Created

All lab files have been created in `C:\github\juice-shop\labs\lesson-02\`:

1. **package.json** - Dependencies and project metadata
2. **encryption-demo.js** - AES-256-GCM encryption demonstration
3. **oauth-server.js** - OAuth 2.0 Authorization Server with PKCE
4. **keyvault-client.js** - Azure Key Vault integration

## Installation

```bash
cd C:\github\juice-shop\labs\lesson-02
npm install
```

## Testing Individual Files

### 1. Encryption Demo

```bash
node encryption-demo.js
```

**Expected Output:**
- AES-256-GCM encryption/decryption demo
- Tampering detection demonstration
- Wrong password rejection
- All security features validated with checkmarks

**Verified:** ✓ All tests pass

### 2. OAuth Server

```bash
node oauth-server.js
```

**Expected Output:**
- OAuth 2.0 server starts on port 4000
- Public key displayed for JWT verification
- Four endpoints available:
  - GET /authorize (authorization with PKCE)
  - POST /token (token exchange)
  - GET /verify (token verification)
  - GET /.well-known/jwks.json (public key)

**To Test OAuth Flow:**

```bash
# Terminal 1: Start OAuth server
node oauth-server.js

# Terminal 2: Test authorization request
# Generate code_verifier and code_challenge
CODE_VERIFIER=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
CODE_CHALLENGE=$(node -e "console.log(require('crypto').createHash('sha256').update('$CODE_VERIFIER').digest('base64url'))")

# Request authorization code
curl "http://localhost:4000/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&state=random-state-123&scope=read"

# Exchange code for token (replace CODE with actual code from redirect)
curl -X POST http://localhost:4000/token \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"CODE\",\"redirect_uri\":\"http://localhost:3000/callback\",\"code_verifier\":\"$CODE_VERIFIER\",\"client_id\":\"test-client\"}"

# Verify token (replace TOKEN with actual token)
curl http://localhost:4000/verify \
  -H "Authorization: Bearer TOKEN"
```

### 3. Key Vault Client

```bash
node keyvault-client.js
```

**Expected Output:**
- Usage instructions and prerequisites
- Example code snippets
- Security features list
- Production recommendations

**Note:** This file requires Azure Key Vault setup to run fully. The demo shows:
- How to initialize the client
- Expected behavior with caching
- Security features explanation

**Prerequisites for Full Testing:**
```bash
# Create Azure Key Vault
az keyvault create --name your-keyvault-name --resource-group your-rg --location eastus

# Create encryption key
az keyvault key create --vault-name your-keyvault-name --name encryption-key --kty RSA

# Grant permissions
az keyvault set-policy --name your-keyvault-name --upn user@example.com --key-permissions get list

# Set environment variables
export KEY_VAULT_NAME=your-keyvault-name
export KEY_NAME=encryption-key

# Authenticate
az login

# Run with actual Key Vault
node keyvault-client.js
```

## Security Features Implemented

### encryption-demo.js
- ✓ AES-256-GCM authenticated encryption
- ✓ Cryptographically secure IV generation (crypto.randomBytes)
- ✓ 12-byte IV (optimal for GCM per NIST SP 800-38D)
- ✓ Authentication tag handling (prevents tampering)
- ✓ PBKDF2 key derivation (600,000 iterations - PCI-DSS v4.0 compliant)
- ✓ Salt generation and storage
- ✓ Proper data format: [salt][iv][tag][ciphertext]

### oauth-server.js
- ✓ OAuth 2.0 Authorization Code Flow
- ✓ PKCE (Proof Key for Code Exchange) with SHA-256
- ✓ Redirect URI whitelist validation
- ✓ 10-minute authorization code expiration
- ✓ Single-use authorization codes
- ✓ State parameter handling (CSRF protection)
- ✓ JWT with RS256 signing (asymmetric)
- ✓ 15-minute access token expiration
- ✓ Proper JWT claims (iss, sub, aud, exp, iat)

### keyvault-client.js
- ✓ DefaultAzureCredential (no hardcoded secrets)
- ✓ In-memory key caching (1-hour TTL)
- ✓ Automatic key refresh before expiration
- ✓ Graceful error handling with fallback
- ✓ Key versioning support
- ✓ Cache invalidation mechanism
- ✓ Background refresh to prevent blocking
- ✓ Proactive refresh 5 minutes before expiration

## File Sizes

```
encryption-demo.js   - 8.8KB (comprehensive comments + working code)
oauth-server.js      - 16KB (full OAuth 2.0 server with PKCE)
keyvault-client.js   - 15KB (production-ready Key Vault client)
package.json         - 789 bytes
```

## Dependencies

All dependencies are in package.json:

```json
{
  "@azure/identity": "^4.0.0",
  "@azure/keyvault-keys": "^4.8.0",
  "express": "^4.18.2",
  "jsonwebtoken": "^9.0.2",
  "crypto": "^1.0.1"
}
```

## Code Quality

- ✓ All files pass JavaScript syntax validation
- ✓ Comprehensive inline documentation
- ✓ Security decisions explained in comments
- ✓ References to standards (NIST, PCI-DSS, RFC, OWASP)
- ✓ Working demos with example output
- ✓ Error handling implemented
- ✓ Production recommendations included

## Usage in Demos

These files are designed for the MS Press GitHub Copilot for Cybersecurity course demos:

1. **Demo 1.1** - Use encryption-demo.js to show Copilot's cryptographic knowledge
2. **Demo 2.1** - Use oauth-server.js to demonstrate OAuth 2.0 with PKCE generation
3. **Demo 3.1** - Use keyvault-client.js to show cloud key management integration

Each file includes:
- Extensive comments explaining security decisions
- References to compliance standards
- Working demonstrations
- Educational value for security professionals

## Next Steps

1. Install dependencies: `npm install`
2. Run encryption demo: `node encryption-demo.js`
3. Test OAuth server: `node oauth-server.js`
4. Review Key Vault demo: `node keyvault-client.js`
5. Use in lesson demos as specified in demo runbook

## References

- Demo Runbook: `C:\github\juice-shop\demos\lesson-02-demo-runbook-final.md`
- Lab README: `C:\github\juice-shop\labs\lesson-02\README.md`
- OWASP Juice Shop: `C:\github\juice-shop\`
