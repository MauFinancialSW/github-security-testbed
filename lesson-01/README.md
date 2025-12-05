# Lesson 01: Vulnerability Detection with GitHub Copilot

## Course: GitHub Copilot for Cybersecurity Specialists

This lesson demonstrates how to use GitHub Copilot for security-focused development, including vulnerability detection, secure code generation, and custom security scanning.

## Folder Structure

```
lesson-01-real/
├── lesson-01-demo-runbook-final.md   # Complete instructor runbook
├── README.md                          # This file
│
├── demo-01-configuration/             # VS Code & Copilot security setup
│   ├── .vscode/settings.json          # Security-focused workspace settings
│   ├── README.md                      # Configuration guide
│   └── vulnerable-pattern-test.js     # Test file for validating config
│
├── demo-02-sql-injection/             # SQL Injection examples
│   ├── vulnerable/
│   │   └── api.js                     # 8 vulnerable endpoints
│   ├── secure/
│   │   └── api.js                     # Secure parameterized versions
│   └── tests/
│       └── sql-injection.test.js      # Security test suite
│
├── demo-03-xss/                       # Cross-Site Scripting examples
│   ├── vulnerable-react-app/
│   │   ├── UserProfile.jsx            # 10 XSS vulnerabilities
│   │   ├── App.jsx                    # Main app component
│   │   └── package.json
│   ├── secure-react-app/
│   │   ├── UserProfile.jsx            # DOMPurify sanitization
│   │   ├── server.js                  # Express with CSP headers
│   │   └── package.json
│   └── tests/
│       └── xss-prevention.test.js     # XSS security tests
│
├── demo-04-custom-scanners/           # Business logic vulnerability scanners
│   ├── idor-app/
│   │   ├── api/documents.js           # IDOR vulnerable endpoints
│   │   ├── db.js                      # Mock database
│   │   ├── server.js                  # Express server
│   │   └── package.json
│   ├── scanner/
│   │   ├── idor-scanner.js            # Cross-tenant access scanner
│   │   ├── race-condition-scanner.js  # Concurrent request scanner
│   │   └── package.json
│   └── reports/
│       └── generate-report.js         # Report generator
│
└── prompts/                           # Reusable Copilot prompts
    ├── sql-detection.md               # SQL injection scanning prompt
    ├── xss-scanning.md                # XSS detection prompt
    └── custom-scanner.md              # Scanner development prompt
```

## Prerequisites

- Visual Studio Code (latest stable)
- GitHub Copilot extension (activated)
- GitHub Copilot Chat extension
- Node.js 20.x LTS
- npm or yarn

## Quick Start

### 1. Install Dependencies

```bash
# SQL Injection demo
cd demo-02-sql-injection/secure
npm install

# XSS demo
cd demo-03-xss/secure-react-app
npm install

# IDOR scanner
cd demo-04-custom-scanners/scanner
npm install
```

### 2. Run Demos

```bash
# Start vulnerable SQL API (port 3000)
cd demo-02-sql-injection/vulnerable && node api.js

# Start secure SQL API (port 3000)
cd demo-02-sql-injection/secure && node api.js

# Start IDOR demo app (port 3001)
cd demo-04-custom-scanners/idor-app && node server.js

# Run IDOR scanner
cd demo-04-custom-scanners/scanner && node idor-scanner.js
```

## Demo Highlights

### Demo 1: Configuration (8 min)
- Configure VS Code workspace for security-focused development
- Enable Copilot security suggestions
- Integrate SAST tools (Semgrep)

### Demo 2: SQL Injection (10 min)
- Identify vulnerable patterns with Copilot Chat
- Refactor to parameterized queries
- Generate security tests

### Demo 3: XSS Prevention (10 min)
- Detect dangerouslySetInnerHTML vulnerabilities
- Implement DOMPurify sanitization
- Configure Content Security Policy headers

### Demo 4: Custom Scanners (12 min)
- Build IDOR scanner for multi-tenant apps
- Create race condition detector
- Generate actionable vulnerability reports

## Copilot Chat Prompts

### SQL Injection Detection
```
Analyze this Express API endpoint for SQL injection vulnerabilities.
Show me: 1) The vulnerable line 2) Attack vectors 3) Secure alternative
```

### XSS Scanning
```
Scan this React component for XSS vulnerabilities. Identify all uses
of dangerouslySetInnerHTML and unsafe DOM manipulation.
```

### Custom Scanner Development
```
Build a custom IDOR scanner that tests cross-tenant access in a
multi-tenant SaaS API. Include severity ratings and remediation steps.
```

## Security Test Commands

```bash
# Test SQL injection protection
npm test --prefix demo-02-sql-injection/tests

# Test XSS prevention
npm test --prefix demo-03-xss/tests

# Run IDOR scan
node demo-04-custom-scanners/scanner/idor-scanner.js

# Run race condition scan
node demo-04-custom-scanners/scanner/race-condition-scanner.js
```

## Key Learning Objectives

By completing this lesson, students will be able to:

1. Configure GitHub Copilot for security-focused suggestions
2. Use Copilot Chat to identify OWASP Top 10 vulnerabilities
3. Generate secure code alternatives with proper input validation
4. Build custom scanners for business logic vulnerabilities
5. Create reusable security prompts for code auditing

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [GitHub Copilot Documentation](https://docs.github.com/copilot)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [DOMPurify](https://github.com/cure53/DOMPurify)

## License

Educational use only. Vulnerable code samples are intentionally insecure for training purposes.
