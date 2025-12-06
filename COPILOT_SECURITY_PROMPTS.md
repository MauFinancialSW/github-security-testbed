# GitHub Copilot Security Prompts Library

> A comprehensive collection of security-focused prompts for GitHub Copilot Chat.
> Use these to detect vulnerabilities, generate secure code, and automate security workflows.

---

## Table of Contents

- [Lesson 1: Vulnerability Detection](#lesson-1-vulnerability-detection)
- [Lesson 2: Security Protocols](#lesson-2-security-protocols)
- [Lesson 3: Automated Security Testing](#lesson-3-automated-security-testing)
- [Lesson 4: Code Review & Threat Modeling](#lesson-4-code-review--threat-modeling)
- [Lesson 5: Compliance & Incident Response](#lesson-5-compliance--incident-response)
- [Bonus: Advanced Security Prompts](#bonus-advanced-security-prompts)

---

## Lesson 1: Vulnerability Detection

### SQL Injection Detection

```
Scan this codebase for SQL injection vulnerabilities. Focus on:
1. String concatenation in SQL queries
2. Unsanitized user input in WHERE clauses
3. Dynamic query building without parameterization
4. ORM queries using raw SQL
5. Stored procedures with dynamic SQL
6. ORDER BY and LIMIT clauses with user input

For each finding: show vulnerable code, explain attack vector, provide parameterized alternative, rate severity, include CWE reference.
```

```
@workspace Analyze all JavaScript files for SQL injection. Show vulnerable lines and fixes.
```

```
Perform a SQL injection security audit on this repository:
1. Find all database query patterns
2. Trace user input to query construction
3. Identify injection points
4. Prioritize by risk (auth bypass > data leak > DoS)
5. Generate fix recommendations with code examples
```

### XSS Detection

```
Analyze this codebase for XSS vulnerabilities. Identify:
1. All uses of dangerouslySetInnerHTML (React)
2. innerHTML assignments without sanitization
3. document.write() with user data
4. eval() and new Function() with user input
5. URL parameters rendered without encoding
6. href/src attributes with javascript: protocol potential
7. Event handler attributes built from user data

For each finding: show vulnerable code, explain XSS type (Stored/Reflected/DOM-based), provide example payload, show sanitized alternative.
```

```
@workspace Scan all React components for XSS vulnerabilities. Focus on dangerouslySetInnerHTML, unsanitized props, URL parameter handling.
```

```
Analyze client-side JavaScript for DOM-based XSS:
1. Find all uses of location.hash, location.search
2. Track data flow to DOM sinks (innerHTML, document.write)
3. Identify missing sanitization
4. Check event handler assignments
```

### Custom Security Scanners

```
Build a custom IDOR vulnerability scanner for a multi-tenant SaaS API.
The scanner should:
1. Accept auth tokens for multiple tenants (A and B)
2. Attempt cross-tenant resource access
3. Detect successful unauthorized access (200 response with data)
4. Generate findings with severity ratings and remediation steps

Test endpoints: GET /api/documents/:id, GET /api/users/:id, POST /api/batch-export
```

```
Generate a race condition scanner for e-commerce operations.
Test scenarios:
1. Coupon code redemption - detect if single-use codes can be reused
2. Balance withdrawal - detect if users can overdraw accounts
3. Inventory purchase - detect if items can be oversold

Send 50 concurrent requests, analyze for successful exploitation.
```

```
Create a scanner to test for authentication bypass vulnerabilities:
1. JWT algorithm confusion (none algorithm)
2. JWT secret brute force (common secrets list)
3. Session fixation
4. Password reset token predictability
5. OAuth state parameter validation
```

---

## Lesson 2: Security Protocols

### OAuth 2.0 & PKCE

```
Create OAuth 2.0 authorization server with PKCE support using Express
```

```
Verify PKCE code_challenge against code_verifier using SHA-256
```

```
Implement secure refresh token rotation with family tracking
```

```
Generate OpenID Connect ID token with required claims including auth_time, nonce, and at_hash
```

### JWT Security

```
Generate JWT token with proper claims and RS256 signing. Include: iss, sub, aud, exp (15 min), iat, jti
```

```
Verify JWT with issuer, audience, and algorithm validation. Prevent algorithm confusion attacks.
```

```
Create JWT middleware that:
1. Validates signature against public key
2. Checks expiration and not-before claims
3. Verifies issuer and audience
4. Extracts user context for downstream handlers
```

### Cryptography

```
Encrypt data using AES-256-GCM with secure IV generation
```

```
Derive encryption key from password using PBKDF2 with PCI-DSS compliance (600,000+ iterations, SHA-512)
```

```
Generate cryptographically secure token for API authentication (32+ bytes entropy)
```

```
Create and verify HMAC for message authentication with timing-safe comparison
```

```
Add Argon2id for password hashing with OWASP recommended parameters
```

### Zero Trust Architecture

```
Create Terraform config for zero trust network segmentation on AWS with:
- Private subnets only
- Network ACLs with explicit deny-all
- Security groups following least privilege
- VPC endpoints for AWS services
- VPC Flow Logs
```

```
Configure Istio service mesh for zero trust mTLS between all services
```

```
Create Istio authorization policy that only allows payment-service to receive requests from order-service on POST /payments/process
```

```
Configure Istio request authentication with JWT validation from identity provider
```

```
Configure circuit breaker that ejects hosts after 5 consecutive 5xx errors
```

---

## Lesson 3: Automated Security Testing

### Security Unit Tests

```
Generate comprehensive OAuth security tests for PKCE flow including:
- Code challenge validation
- Redirect URI attack prevention
- Authorization code replay prevention
- State parameter CSRF protection
```

```
Create security unit tests for this authentication endpoint covering:
- Brute force protection
- Account lockout
- Password complexity
- Session management
- Token expiration
```

### Fuzzing

```
Create fuzzing test harness for API input validation with mutation strategies for SQL injection, XSS, and command injection payloads
```

```
Build a mutation-based fuzzer that:
1. Takes seed inputs from corpus
2. Applies bit flip, byte replace, insert, delete mutations
3. Includes security-focused dictionaries
4. Detects crashes and hangs
5. Reports findings with reproduction steps
```

### SAST/DAST

```
Create Semgrep rules for detecting security vulnerabilities including SQL injection, XSS, command injection, and hardcoded credentials
```

```
Build a DAST scanner that tests for:
1. SQL injection with time-based blind detection
2. XSS with polyglot payloads
3. Missing security headers
4. SSRF via URL parameters
5. Authentication bypass
```

### CI/CD Security

```
Create GitHub Actions workflow for comprehensive security testing with:
1. Secret detection (TruffleHog)
2. Dependency scanning (npm audit)
3. SAST (Semgrep, CodeQL)
4. Container scanning (Trivy)
5. IaC scanning (Checkov)
6. Security gate that fails on critical findings
```

---

## Lesson 4: Code Review & Threat Modeling

### Security Code Review

```
Review this authentication code for security vulnerabilities including timing attacks, credential handling, and session management
```

```
Check for OWASP Top 10 issues in this API endpoint
```

```
Analyze this code for race conditions and timing attacks
```

```
Review this file upload handler for:
1. Path traversal vulnerabilities
2. File type validation bypass
3. Size limit enforcement
4. Malicious content scanning
```

### Threat Modeling

```
Create STRIDE threat model for this authentication flow
```

```
Identify attack vectors for this microservice architecture
```

```
Generate threat model for this payment processing system covering:
1. Spoofing threats to user identity
2. Tampering threats to transaction data
3. Repudiation threats to audit logs
4. Information disclosure of PII/PCI data
5. Denial of service vectors
6. Elevation of privilege paths
```

```
Create attack tree for account takeover scenario
```

### Compliance & Reporting

```
Generate compliance report for OWASP Top 10 and PCI-DSS requirements
```

```
Create security audit checklist for SOC 2 Type II compliance
```

```
Map these findings to CWE identifiers and CVSS scores
```

---

## Lesson 5: Compliance & Incident Response

### Infrastructure as Code

```
Create secure Terraform configuration for EC2 with CIS benchmarks including:
- Encrypted root volume with KMS
- IMDSv2 required
- Private subnet placement
- Least privilege IAM role
- Security group with minimal ingress
```

```
Generate hardened S3 bucket configuration with:
- Server-side encryption (SSE-KMS)
- Block public access
- Versioning enabled
- Access logging
- Lifecycle policies
```

### Compliance Checking

```
Create CIS benchmark compliance checker for AWS resources covering IAM, S3, CloudTrail, VPC
```

```
Build NIST 800-53 control validator for this infrastructure
```

```
Generate PCI-DSS requirement checklist for this payment application
```

### STIG Remediation

```
Create STIG remediation script for Linux hardening covering:
- SSH hardening (no root login, protocol 2, idle timeout)
- Password policies (complexity, history, lockout)
- Audit configuration
- File permissions
- FIPS mode
```

### Incident Response

```
Create incident response automation playbook for compromised EC2 instance:
1. Detect: Collect instance metadata and user activity
2. Contain: Isolate instance, disable access keys
3. Collect: Create forensic snapshots, preserve logs
4. Notify: Alert security team via Slack/PagerDuty
5. Document: Generate incident timeline
```

```
Build automated response for GuardDuty findings that:
1. Parses finding type and severity
2. Executes appropriate containment
3. Preserves evidence to S3
4. Creates incident ticket
5. Notifies on-call
```

---

## Bonus: Advanced Security Prompts

### API Security

```
Generate API security test suite for this REST API covering:
1. Authentication bypass attempts
2. Authorization boundary testing
3. Rate limiting verification
4. Input validation (all OWASP categories)
5. Response data leakage
6. Mass assignment vulnerabilities
7. BOLA/IDOR testing
```

```
Create API gateway security configuration with:
- Request validation
- Rate limiting per client
- JWT validation
- IP allowlisting
- Request/response logging
- WAF rules
```

```
Build GraphQL security scanner that tests for:
1. Introspection exposure
2. Query depth attacks
3. Batch query abuse
4. Authorization bypass via nested queries
5. Field-level injection
```

### Container Security

```
Create Dockerfile security best practices checker that detects:
1. Running as root
2. Using latest tag
3. Exposing unnecessary ports
4. Hardcoded secrets
5. Missing health checks
6. Unverified base images
```

```
Generate Kubernetes security policies (PSP/PSA) for:
1. Non-root containers
2. Read-only filesystem
3. Dropped capabilities
4. Network policies
5. Resource limits
```

```
Create container runtime security monitoring with:
1. Syscall filtering (seccomp)
2. File integrity monitoring
3. Network anomaly detection
4. Process execution logging
```

### Cloud Security

```
Build AWS security audit script covering:
1. Public S3 buckets
2. Overly permissive security groups
3. Unencrypted EBS volumes
4. IAM users without MFA
5. Unused access keys
6. CloudTrail disabled regions
7. Default VPC usage
```

```
Create Azure security posture assessment for:
1. Storage account public access
2. NSG rule analysis
3. Key Vault access policies
4. Azure AD conditional access gaps
5. Defender for Cloud recommendations
```

```
Generate GCP security checklist covering:
1. Service account key rotation
2. VPC firewall rules
3. Cloud Storage bucket ACLs
4. IAM policy bindings
5. Cloud Audit Logs configuration
```

### Secure Development

```
Create secure coding guidelines document for this project covering:
1. Input validation patterns
2. Output encoding requirements
3. Authentication best practices
4. Session management
5. Cryptographic standards
6. Error handling (no sensitive data in errors)
7. Logging requirements (audit trail)
```

```
Generate security requirements from these user stories for threat-driven development
```

```
Create pre-commit hooks that check for:
1. Hardcoded secrets (API keys, passwords)
2. SQL injection patterns
3. XSS vulnerable code
4. Insecure dependencies
5. Debug code left in
```

### Penetration Testing

```
Generate penetration test plan for this web application covering reconnaissance, scanning, exploitation, and reporting phases
```

```
Create automated recon script that:
1. Enumerates subdomains
2. Scans for open ports
3. Fingerprints technologies
4. Discovers exposed files/directories
5. Checks for known CVEs
```

```
Build exploitation validation script that safely confirms these vulnerabilities:
1. SQL injection (time-based confirmation)
2. XSS (DOM observation)
3. SSRF (callback server)
4. XXE (OOB data exfiltration)
```

### Security Automation

```
Create security chatbot that:
1. Answers security policy questions
2. Triages security reports
3. Provides remediation guidance
4. Escalates critical issues
```

```
Build automated vulnerability prioritization system using:
1. CVSS score
2. Asset criticality
3. Exploit availability
4. Network exposure
5. Data sensitivity
```

```
Generate security metrics dashboard data collector for:
1. Mean time to detect (MTTD)
2. Mean time to respond (MTTR)
3. Vulnerability aging
4. Patch compliance
5. Security training completion
```

### Forensics & Investigation

```
Create log analysis queries for detecting:
1. Brute force attacks
2. Privilege escalation
3. Data exfiltration
4. Lateral movement
5. Persistence mechanisms
```

```
Build memory forensics script that:
1. Captures volatile data
2. Lists running processes
3. Extracts network connections
4. Identifies injected code
5. Recovers encryption keys
```

```
Generate timeline reconstruction script from:
1. System logs
2. Application logs
3. Network captures
4. File system metadata
5. Registry (Windows)
```

### Security Training

```
Create interactive security training module for developers covering:
1. OWASP Top 10 with code examples
2. Secure coding challenges
3. Vulnerability identification quiz
4. Fix-the-code exercises
```

```
Generate phishing awareness training content with:
1. Example phishing emails
2. Red flags to identify
3. Reporting procedures
4. Safe link verification
```

```
Build capture-the-flag challenge for:
1. SQL injection (beginner to advanced)
2. XSS (reflected, stored, DOM)
3. Authentication bypass
4. Cryptographic attacks
5. Reverse engineering
```

---

## Quick Reference Card

### Detection Prompts
| Vulnerability | Prompt Start |
|--------------|--------------|
| SQL Injection | "Scan for SQL injection focusing on string concatenation..." |
| XSS | "Analyze for XSS including innerHTML, dangerouslySetInnerHTML..." |
| IDOR | "Test for insecure direct object references in API endpoints..." |
| Auth Bypass | "Check authentication for bypass vulnerabilities..." |
| SSRF | "Identify server-side request forgery in URL handling..." |

### Generation Prompts
| Asset | Prompt Start |
|-------|--------------|
| Secure API | "Create Express API with authentication, rate limiting..." |
| JWT Handler | "Generate JWT middleware with RS256, issuer validation..." |
| Terraform | "Create CIS-compliant Terraform for AWS..." |
| Security Tests | "Generate security test suite covering OWASP Top 10..." |
| IR Playbook | "Create incident response automation for..." |

### Review Prompts
| Focus | Prompt Start |
|-------|--------------|
| Code Review | "Review this code for security vulnerabilities..." |
| Threat Model | "Create STRIDE threat model for..." |
| Compliance | "Check compliance with CIS/NIST/PCI-DSS..." |
| Architecture | "Identify attack vectors in this architecture..." |

---

## Tips for Effective Security Prompts

1. **Be Specific**: Include vulnerability types, frameworks, and compliance standards
2. **Request Structure**: Ask for JSON output, severity ratings, CWE references
3. **Provide Context**: Mention the tech stack, threat model, and compliance requirements
4. **Ask for Examples**: Request attack payloads and secure code alternatives
5. **Iterate**: Use follow-up prompts to drill deeper into findings
6. **Verify**: Always validate Copilot's suggestions against known security standards

---

*Happy Secure Coding!*
