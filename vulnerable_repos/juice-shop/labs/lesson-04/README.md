# Lesson 04 Lab Files: Security Code Review & Auditing

This directory contains lab materials for Lesson 04 of the MS Press GitHub Copilot for Cybersecurity Professionals course.

## Overview

This lesson demonstrates using GitHub Copilot Chat and security tools for comprehensive security analysis workflows including:

1. Interactive security code reviews with Copilot Chat
2. STRIDE threat modeling
3. Custom security linters with Semgrep
4. Automated vulnerability analysis

## Directory Structure

```
lesson-04/
├── auth-api/                 # Vulnerable Express.js API for code review demos
│   ├── server.js            # Main API with 7 intentional vulnerabilities
│   ├── middleware/
│   │   └── auth.js          # Vulnerable authentication middleware
│   ├── package.json         # Dependencies
│   └── README.md            # Detailed vulnerability documentation
│
├── linters/                  # Custom Semgrep security rules
│   ├── azure-storage-auth.yml           # Detects hardcoded Azure connection strings
│   ├── azure-managed-identity.yml       # Detects missing managed identity usage
│   └── hardcoded-secrets.yml            # Generic secret detection patterns
│
├── test-cases/              # Code samples for testing linters
│   ├── vulnerable.js        # Code that SHOULD trigger linter rules
│   └── secure.js            # Code that should NOT trigger rules
│
└── README.md                # This file
```

## Lab Components

### 1. Vulnerable Auth API (`auth-api/`)

A deliberately insecure Express.js REST API demonstrating common authentication/authorization vulnerabilities.

**Intentional Vulnerabilities:**
- CWE-798: Hardcoded JWT secret
- CWE-327: JWT algorithm confusion (HS256/RS256)
- CWE-613: Missing token expiration enforcement
- CWE-639: Authorization bypass via JWT payload manipulation
- CWE-209: Information disclosure in error messages
- CWE-89: SQL injection in search endpoint

**Usage:**
```bash
cd auth-api
npm install
npm start

# Test endpoints
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "password": "test"}'
```

See `auth-api/README.md` for detailed vulnerability descriptions and exploitation examples.

### 2. Custom Security Linters (`linters/`)

Semgrep rules detecting organization-specific security anti-patterns, focusing on Azure security best practices.

**Rules:**

#### `azure-storage-auth.yml`
Detects hardcoded Azure Storage connection strings.

**Matches:**
```javascript
const conn = "DefaultEndpointsProtocol=https;AccountName=store;AccountKey=abc123==";
```

**Fix:**
```javascript
const { DefaultAzureCredential } = require("@azure/identity");
const credential = new DefaultAzureCredential();
const client = new BlobServiceClient(`https://${accountName}.blob.core.windows.net`, credential);
```

#### `azure-managed-identity.yml`
Detects Azure service clients not using DefaultAzureCredential.

**Targets:** Azure Storage, Cosmos DB, Service Bus

#### `hardcoded-secrets.yml`
Generic patterns for hardcoded secrets:
- API keys
- JWT secrets
- Database passwords
- AWS credentials
- High-entropy secrets

**Usage:**
```bash
# Install Semgrep
pip install semgrep

# Run all rules against test cases
semgrep --config linters/ test-cases/

# Run specific rule
semgrep --config linters/azure-storage-auth.yml test-cases/vulnerable.js

# Output in different formats
semgrep --config linters/ test-cases/ --json
semgrep --config linters/ test-cases/ --sarif -o results.sarif
```

### 3. Test Cases (`test-cases/`)

Code samples for validating Semgrep rules.

**`vulnerable.js`** - Should trigger 20+ findings:
- 3 Azure Storage connection strings
- 4 hardcoded API keys
- 3 hardcoded JWT secrets
- 3 database passwords with credentials
- 2 AWS credentials
- 4 high-entropy secrets
- 3 missing managed identity issues

**`secure.js`** - Should trigger 0 findings:
- Uses DefaultAzureCredential for Azure services
- Loads secrets from environment variables
- Uses Azure Key Vault for sensitive data
- Demonstrates secure patterns

**Validation:**
```bash
# Vulnerable code should show findings
semgrep --config linters/ test-cases/vulnerable.js
# Expected: 20+ findings

# Secure code should be clean
semgrep --config linters/ test-cases/secure.js
# Expected: 0 findings
```

## Lab Exercises

### Exercise 1: Interactive Security Code Review

Use GitHub Copilot Chat to review the vulnerable API:

1. Open `auth-api/server.js` in VS Code
2. Open Copilot Chat panel
3. Use this prompt:

```
I need a security code review of this Express.js API. The architecture:

- Express REST API with JWT authentication
- Role-based access control (admin, user roles)
- User profile endpoints with PII
- Deployed to Azure App Service with internet access
- Processes sensitive user data

Focus on authentication and authorization vulnerabilities. Use OWASP Top 10 as framework.
```

4. Follow up with specific questions:
   - "Show me the JWT validation code. Does it properly verify the signature?"
   - "Check the authorization middleware. Can a user escalate privileges?"
   - "Are there any SQL injection vulnerabilities?"

5. Generate a security report:
```
Generate a security review report in markdown format with:
- Executive summary
- Detailed findings with CWE references
- Severity ratings (Critical/High/Medium/Low)
- Remediation recommendations with code examples
- OWASP Top 10 mapping
```

### Exercise 2: STRIDE Threat Modeling

Generate a threat model for the API:

```
Generate a STRIDE threat model for this API architecture. Consider:
- API is internet-accessible
- Uses JWT bearer token authentication
- Stores user PII in MongoDB
- Deployed as single Azure App Service instance

Provide specific attack scenarios for each STRIDE category.
```

### Exercise 3: Custom Linter Development

Extend the existing rules:

1. Create a new rule: `linters/custom-rule.yml`
2. Test against sample code
3. Integrate into CI/CD

**Example:** Detect missing rate limiting on authentication endpoints

```
Prompt: "Generate a Semgrep rule that detects Express.js routes handling authentication
(like /login, /register) that don't use rate limiting middleware like express-rate-limit."
```

### Exercise 4: Semgrep CI/CD Integration

Add Semgrep to GitHub Actions:

```yaml
# .github/workflows/security-linting.yml
name: Security Linting

on:
  pull_request:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Semgrep
        run: pip install semgrep

      - name: Run custom security rules
        run: |
          semgrep --config labs/lesson-04/linters/ \
            --error \
            --sarif \
            --output semgrep-results.sarif \
            .

      - name: Upload to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep-results.sarif
```

## Learning Objectives

After completing these labs, you should be able to:

1. Use GitHub Copilot Chat for interactive security code reviews
2. Identify authentication and authorization vulnerabilities
3. Apply STRIDE threat modeling framework
4. Create custom security linters for organization-specific policies
5. Integrate security scanning into CI/CD pipelines
6. Map vulnerabilities to OWASP Top 10 and CWE classifications
7. Generate security reports and documentation with AI assistance

## Prerequisites

**Required Tools:**
- Node.js 18+
- Python 3.8+ (for Semgrep)
- VS Code with GitHub Copilot Chat extension
- Git CLI

**Installation:**
```bash
# Verify Node.js
node --version

# Install Semgrep
pip install semgrep
semgrep --version

# Install API dependencies
cd auth-api
npm install
```

## Common Issues

**Semgrep not finding rules:**
```bash
# Use absolute path or relative path from repo root
semgrep --config labs/lesson-04/linters/ .
```

**False positives in tests:**
```javascript
// Add nosemgrep comment to suppress specific rules
const TEST_SECRET = 'test-only'; // nosemgrep: hardcoded-jwt-secret
```

**API fails to start:**
```bash
# Check if port 3000 is already in use
lsof -ti:3000 | xargs kill -9  # macOS/Linux
netstat -ano | findstr :3000   # Windows

# Or use a different port
PORT=3001 npm start
```

## Additional Resources

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Azure Security Best Practices](https://docs.microsoft.com/azure/security/fundamentals/best-practices-and-patterns)
- [JWT Best Practices (RFC 8725)](https://tools.ietf.org/html/rfc8725)
- [STRIDE Threat Modeling](https://docs.microsoft.com/azure/security/develop/threat-modeling-tool-threats)

## Demo Runbook

This lab corresponds to Lesson 04 in `demos/lesson-04-demo-runbook-final.md`. See the runbook for:
- Step-by-step demo scripts
- Timing allocations (40 minutes total)
- Copilot prompt templates
- Expected outputs
- Teaching points

## License

MIT License - For educational purposes only. See main repository LICENSE file.

---

**WARNING:** The code in `auth-api/` contains intentional security vulnerabilities for educational purposes. DO NOT deploy to production or any internet-accessible environment!
