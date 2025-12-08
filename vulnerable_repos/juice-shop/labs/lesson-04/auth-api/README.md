# Vulnerable Authentication API - Security Code Review Lab

## WARNING: INTENTIONALLY VULNERABLE CODE

This Express.js API contains **deliberate security vulnerabilities** for educational purposes. It is designed for security code review training in the MS Press GitHub Copilot for Cybersecurity course.

**DO NOT deploy this code to production or any internet-accessible environment!**

## Purpose

This API demonstrates common authentication and authorization vulnerabilities that security professionals should be able to identify during code reviews. It serves as the basis for:

1. Interactive security code review with GitHub Copilot Chat
2. STRIDE threat modeling exercises
3. Automated security scanning demonstrations
4. Secure code remediation practice

## Intentional Vulnerabilities

### 1. Hardcoded JWT Secret (CWE-798)
**Location:** `server.js` line 30
```javascript
const JWT_SECRET = 'super-secret-key-12345';
```

**Risk:** Critical - Allows anyone with access to the source code to forge valid JWT tokens.

**Exploitation:**
```javascript
const jwt = require('jsonwebtoken');
const forgedToken = jwt.sign({ userId: 1, role: 'admin' }, 'super-secret-key-12345');
```

**Fix:** Use environment variables or a secure secret management service (Azure Key Vault, HashiCorp Vault).

---

### 2. JWT Algorithm Confusion (CWE-327)
**Location:** `middleware/auth.js` line 42
```javascript
const decoded = jwt.verify(token, JWT_SECRET);
```

**Risk:** High - Allows HS256/RS256 algorithm confusion attack.

**Exploitation:** An attacker can create an RS256 token using the public key (the hardcoded secret) as the HMAC secret.

**Fix:** Specify allowed algorithms explicitly:
```javascript
const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```

---

### 3. Missing Token Expiration (CWE-613)
**Location:** `server.js` line 75
```javascript
const token = jwt.sign({ userId, username, role }, JWT_SECRET);
// Missing: expiresIn option
```

**Risk:** Medium - Tokens never expire, increasing the window for token theft and replay attacks.

**Fix:** Set token expiration:
```javascript
const token = jwt.sign({ userId, username, role }, JWT_SECRET, { expiresIn: '1h' });
```

---

### 4. Authorization Bypass (CWE-639)
**Location:** `middleware/auth.js` line 48-56
```javascript
req.user = {
  userId: decoded.userId,
  username: decoded.username,
  role: decoded.role  // Trusts JWT payload!
};
```

**Risk:** Critical - Users can escalate privileges by modifying the role claim in their JWT.

**Exploitation:**
```javascript
// User creates their own JWT with admin role
const maliciousToken = jwt.sign(
  { userId: 2, username: 'attacker', role: 'admin' },
  'super-secret-key-12345'  // Known from source code
);
```

**Fix:** Always validate role against the database, not the JWT payload.

---

### 5. SQL Injection (CWE-89)
**Location:** `server.js` line 55, 146
```javascript
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**Risk:** Critical - Allows arbitrary SQL execution.

**Exploitation:**
```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "' OR '1'='1"}'
```

**Fix:** Use parameterized queries or an ORM.

---

### 6. Information Disclosure (CWE-209)
**Location:** `server.js` line 88-94, `middleware/auth.js` line 75-81
```javascript
res.status(500).json({
  error: error.message,
  stack: error.stack,  // Exposes implementation details!
  query: req.body
});
```

**Risk:** Medium - Leaks sensitive system information to attackers.

**Fix:** Return generic error messages:
```javascript
res.status(500).json({ error: 'Internal server error' });
```

---

## Setup Instructions

### Installation
```bash
cd labs/lesson-04/auth-api
npm install
```

### Running the API
```bash
npm start
# Server starts on http://localhost:3000
```

### Testing Endpoints

**Login (returns JWT):**
```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "password123"}'
```

**Access Profile (requires auth):**
```bash
curl http://localhost:3000/api/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Access Admin Endpoint (requires admin role):**
```bash
curl http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Exploit Admin Bypass:**
```bash
# Create forged admin token
node -e "const jwt = require('jsonwebtoken'); console.log(jwt.sign({userId: 999, username: 'hacker', role: 'admin'}, 'super-secret-key-12345'));"

# Use it to access admin endpoint
curl http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer YOUR_FORGED_TOKEN"
```

## Lab Exercises

### Exercise 1: Security Code Review
Use GitHub Copilot Chat to perform a comprehensive security review:

1. Open `server.js` in VS Code
2. Open Copilot Chat panel
3. Prompt: "Perform a security code review of this Express API. Focus on authentication and authorization vulnerabilities. Use OWASP Top 10 as framework."
4. Document all findings with CWE references

### Exercise 2: STRIDE Threat Modeling
Generate a STRIDE threat model for this API:

1. Prompt: "Generate a STRIDE threat model for this API. Consider: internet-accessible, JWT authentication, MongoDB backend, Azure deployment."
2. Review each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
3. Identify specific attack scenarios

### Exercise 3: Automated Remediation
Ask Copilot to generate secure code:

1. Prompt: "Rewrite the authenticate middleware to fix all security vulnerabilities. Use best practices for JWT validation and role-based access control."
2. Compare the vulnerable vs. secure implementations
3. Identify the key differences

## OWASP Top 10 Mapping

| Vulnerability | OWASP 2021 Category | CWE | Severity |
|---------------|---------------------|-----|----------|
| Hardcoded JWT Secret | A07:2021 - Identification and Authentication Failures | CWE-798 | Critical |
| JWT Algorithm Confusion | A07:2021 - Identification and Authentication Failures | CWE-327 | High |
| Missing Token Expiration | A07:2021 - Identification and Authentication Failures | CWE-613 | Medium |
| Authorization Bypass | A01:2021 - Broken Access Control | CWE-639 | Critical |
| SQL Injection | A03:2021 - Injection | CWE-89 | Critical |
| Information Disclosure | A05:2021 - Security Misconfiguration | CWE-209 | Medium |

## Learning Objectives

After completing this lab, you should be able to:

1. Identify common authentication/authorization vulnerabilities through code review
2. Understand the difference between authentication (who you are) and authorization (what you can do)
3. Recognize when cryptographic operations are performed incorrectly
4. Apply STRIDE threat modeling to web APIs
5. Use GitHub Copilot Chat effectively for security analysis
6. Map vulnerabilities to OWASP Top 10 and CWE classifications

## Additional Resources

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [STRIDE Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

## License

MIT License - For educational purposes only. See main repository LICENSE file.
