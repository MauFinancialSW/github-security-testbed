# Lesson 03: Automated Security Testing

## Course: GitHub Copilot for Cybersecurity Specialists

---

## Overview

This lesson covers automated security testing techniques including OAuth security tests, fuzzing, SAST/DAST, and CI/CD security pipelines. Learn how to use Copilot to generate comprehensive security testing frameworks.

---

## Demos

### Demo 01: OAuth Security Tests
**Location:** `demo-01-oauth-tests/`

**Files:**
- `oauth-security-tests.js` - Comprehensive OAuth 2.0 security test suite

**Test Categories:**
- PKCE validation tests
- Redirect URI attack prevention
- Authorization code replay prevention
- State parameter CSRF protection
- Token security validation

**Copilot Prompt:**
```
Generate comprehensive OAuth security tests for PKCE flow
```

**Run Tests:**
```bash
node demo-01-oauth-tests/oauth-security-tests.js
```

---

### Demo 02: Fuzzing Framework
**Location:** `demo-02-fuzzing/`

**Files:**
- `fuzzer.js` - Mutation-based security fuzzer
- `corpus/sample-inputs.txt` - Seed inputs for fuzzing

**Features:**
- Mutation strategies (bit flip, byte replace, insert, delete)
- Security-focused dictionaries (SQL injection, XSS, command injection)
- Coverage-guided fuzzing simulation
- Crash detection and reporting

**Copilot Prompt:**
```
Create fuzzing test harness for API input validation
```

**Run Fuzzer:**
```bash
node demo-02-fuzzing/fuzzer.js
```

---

### Demo 03: SAST/DAST
**Location:** `demo-03-sast-dast/`

**Files:**
- `semgrep-rules.yaml` - Custom Semgrep security rules
- `codeql/queries/sql-injection.ql` - CodeQL SQL injection detection
- `dast-scanner.js` - Dynamic application security scanner

**SAST (Static) Features:**
- SQL injection detection
- XSS detection
- Command injection detection
- Weak cryptography detection
- Hardcoded credential detection

**DAST (Dynamic) Features:**
- Live SQL injection testing
- XSS payload testing
- Security header validation
- SSRF testing
- Authentication testing

**Copilot Prompt:**
```
Create Semgrep rules for detecting security vulnerabilities
```

**Run SAST:**
```bash
semgrep scan --config demo-03-sast-dast/semgrep-rules.yaml .
```

**Run DAST:**
```bash
node demo-03-sast-dast/dast-scanner.js
```

---

### Demo 04: CI/CD Security Pipeline
**Location:** `demo-04-cicd-pipeline/`

**Files:**
- `.github/workflows/security-pipeline.yml` - Complete security pipeline

**Pipeline Stages:**
1. Secret Detection (TruffleHog, GitLeaks)
2. Dependency Scanning (npm audit, Snyk, OWASP)
3. SAST (CodeQL, Semgrep)
4. Container Scanning (Trivy, Grype)
5. DAST (ZAP)
6. Security Unit Tests
7. IaC Scanning (Checkov, KICS)
8. Security Gate
9. Compliance Reporting

**Copilot Prompt:**
```
Create GitHub Actions workflow for comprehensive security testing
```

---

## Prerequisites

```bash
# Install Node.js dependencies
npm install

# Install Semgrep
pip install semgrep

# Install CodeQL CLI (optional)
# https://github.com/github/codeql-cli-binaries

# For DAST, start target application
npm start
```

---

## Security Testing Best Practices

### 1. Shift Left
- Run SAST in IDE with Copilot suggestions
- Pre-commit hooks for secret detection
- Unit tests for security requirements

### 2. Defense in Depth
- Multiple overlapping scanners
- Both SAST and DAST
- Dependency and container scanning

### 3. Continuous Monitoring
- Scheduled security scans
- Dependency update alerts
- Security gate enforcement

### 4. Actionable Results
- Prioritize by severity
- Link to CWE/OWASP references
- Provide remediation guidance

---

## Fuzzing Dictionary Categories

| Category | Purpose | Example Payloads |
|----------|---------|------------------|
| sqlInjection | Database attack testing | `' OR '1'='1` |
| xss | Cross-site scripting | `<script>alert(1)</script>` |
| commandInjection | OS command execution | `; ls -la` |
| pathTraversal | File system access | `../../../etc/passwd` |
| ssrf | Internal network access | `http://169.254.169.254/` |
| formatString | Memory corruption | `%s%s%s%s%s` |

---

## CI/CD Security Tools

| Tool | Type | Purpose |
|------|------|---------|
| TruffleHog | Secret Detection | Finds leaked credentials |
| Snyk | Dependency | Known vulnerability detection |
| CodeQL | SAST | Semantic code analysis |
| Semgrep | SAST | Pattern-based scanning |
| Trivy | Container | Image vulnerability scanning |
| ZAP | DAST | Runtime security testing |
| Checkov | IaC | Terraform/K8s security |

---

## Common Vulnerabilities Detected

1. **SQL Injection** (CWE-89)
2. **Cross-Site Scripting** (CWE-79)
3. **Command Injection** (CWE-78)
4. **Path Traversal** (CWE-22)
5. **Weak Cryptography** (CWE-327)
6. **Hardcoded Credentials** (CWE-798)
7. **Missing Security Headers** (CWE-693)
8. **Server-Side Request Forgery** (CWE-918)
