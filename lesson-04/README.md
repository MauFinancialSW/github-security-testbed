# Lesson 04: Security Code Review, Threat Modeling, Auditing

## Course: GitHub Copilot for Cybersecurity Specialists

---

## Overview

This lesson covers advanced security practices including code review techniques, compliance reporting, custom security linters, and dependency analysis. Learn how to use Copilot for thorough security assessments.

---

## Demos

### Auth API Security Demo
**Location:** `demos/auth-api/`

**Files:**
- `server.js` - Production-ready authentication API
- `middleware/security.js` - Comprehensive security middleware

**Security Features:**
- Rate limiting with exponential backoff
- Account lockout protection
- Secure session management
- Input validation and sanitization
- Comprehensive audit logging
- CSRF protection
- Security headers

**Run Demo:**
```bash
node demos/auth-api/server.js
# API available at http://localhost:3000
```

---

### Compliance Reporting
**Location:** `scripts/compliance-report.js`

**Features:**
- OWASP Top 10 coverage analysis
- PCI-DSS requirement mapping
- CWE categorization
- HTML and JSON report generation
- Remediation tracking

**Copilot Prompt:**
```
Generate compliance report for OWASP Top 10 and PCI-DSS requirements
```

**Run:**
```bash
node scripts/compliance-report.js
```

---

### Custom Security Linter
**Location:** `linters/security-linter.js`

**Detection Rules:**
- SQL injection (string concatenation)
- XSS (innerHTML, document.write)
- Command injection (exec, spawn)
- Weak cryptography (MD5, SHA1, ECB mode)
- Hardcoded credentials
- Path traversal
- Information disclosure

**Run:**
```bash
node linters/security-linter.js ./src
# Or with SARIF output:
node linters/security-linter.js ./src --sarif > results.sarif
```

---

### Dependency Analyzer
**Location:** `scripts/dependency-analyzer.js`

**Features:**
- Vulnerability detection
- License compliance checking
- Outdated package detection
- Dependency tree visualization

**Run:**
```bash
node scripts/dependency-analyzer.js .
# Or JSON output:
node scripts/dependency-analyzer.js . --json > analysis.json
```

---

## Security Middleware Reference

### Available Middleware

| Middleware | Purpose |
|------------|---------|
| `requestId` | Unique request ID for tracing |
| `securityHeaders` | CSP, HSTS, X-Frame-Options |
| `secureCors` | Secure CORS configuration |
| `RateLimiter` | Sliding window rate limiting |
| `sanitizeInput` | Input sanitization |
| `CsrfProtection` | CSRF token validation |
| `ipFilter` | IP whitelist/blacklist |
| `securityLogger` | Security-focused logging |

### Usage Example

```javascript
const {
  requestId,
  securityHeaders,
  RateLimiter,
  sanitizeInput
} = require('./middleware/security');

const app = express();

app.use(requestId);
app.use(securityHeaders());
app.use(sanitizeInput());

const limiter = new RateLimiter({
  windowMs: 60000,
  maxRequests: 100
});
app.use(limiter.middleware());
```

---

## OWASP Top 10 (2021) Coverage

| ID | Category | Detection |
|----|----------|-----------|
| A01 | Broken Access Control | Auth tests, IDOR scanning |
| A02 | Cryptographic Failures | Weak crypto linting |
| A03 | Injection | SQL, XSS, Command injection |
| A04 | Insecure Design | Threat modeling |
| A05 | Security Misconfiguration | Header validation |
| A06 | Vulnerable Components | Dependency analysis |
| A07 | Auth Failures | Auth API testing |
| A08 | Integrity Failures | Dependency signing |
| A09 | Logging Failures | Audit log review |
| A10 | SSRF | URL validation |

---

## Custom Linter Rules

### Adding New Rules

```javascript
const customRules = {
  'no-custom-issue': {
    severity: 'error',
    message: 'Description of the issue',
    cwe: 'CWE-XXX',
    patterns: [
      /pattern-to-match/g
    ]
  }
};

const linter = new SecurityLinter({
  rules: customRules
});
```

### Rule Properties

| Property | Type | Description |
|----------|------|-------------|
| severity | string | 'error' or 'warning' |
| message | string | Issue description |
| cwe | string | CWE identifier |
| patterns | RegExp[] | Detection patterns |
| exceptions | string[] | Strings to skip |
| check | function | Custom check function |

---

## Compliance Report Output

### HTML Report
Generated at `reports/compliance-report.html`:
- Visual dashboard
- OWASP coverage chart
- Findings list with severity
- Remediation guidance

### JSON Report
Generated at `reports/compliance-report.json`:
- Machine-readable format
- CI/CD integration ready
- Full finding details
- Score calculations

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Run Security Linter
  run: node linters/security-linter.js ./src --sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif

- name: Check Dependencies
  run: node scripts/dependency-analyzer.js .
```

---

## Prompts Reference

### Code Review Prompts

```
Review this authentication code for security vulnerabilities
```

```
Check for OWASP Top 10 issues in this API endpoint
```

```
Analyze this code for race conditions and timing attacks
```

### Threat Modeling Prompts

```
Create STRIDE threat model for this authentication flow
```

```
Identify attack vectors for this microservice architecture
```

---

## Best Practices

1. **Regular Audits**: Run security linters in CI/CD pipeline
2. **Dependency Updates**: Monitor and update vulnerable packages
3. **Compliance Tracking**: Generate reports for each release
4. **Code Review**: Use Copilot for security-focused reviews
5. **Threat Modeling**: Document threats during design phase
