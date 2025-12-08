# Lesson 01: Vulnerability Detection with GitHub Copilot

**Duration:** 40 minutes

## Learning Objectives

- Configure GitHub Copilot for security-focused development
- Detect SQL injection vulnerabilities with Copilot assistance
- Identify and prevent XSS vulnerabilities
- Build custom vulnerability scanners for IDOR detection

## Lab Files

This lesson uses the main Juice Shop codebase. Key vulnerable files:

| File | Vulnerability | Demo |
|------|---------------|------|
| `routes/login.ts` | SQL Injection | Demo 2 |
| `frontend/src/app/search-result/search-result.component.ts` | Reflected XSS | Demo 3 |
| `routes/userProfile.ts` | IDOR | Demo 4 |

## Setup

```bash
# Ensure Juice Shop is running
npm install
npm run serve:dev

# Access at http://localhost:3000
```

## Demo Flow

### Demo 1: Configuring Copilot for Security (8 min)
- Install security extensions
- Configure workspace settings
- Integrate SAST tools

### Demo 2: SQL Injection Detection (10 min)
- Analyze `routes/login.ts` for SQL injection
- Generate parameterized query fix
- Create security unit tests

### Demo 3: XSS Detection and Prevention (10 min)
- Scan for `dangerouslySetInnerHTML` patterns
- Implement DOMPurify sanitization
- Add Content Security Policy headers

### Demo 4: Custom IDOR Scanner (12 min)
- Analyze multi-tenant authorization gaps
- Build custom scanner with Copilot
- Generate actionable security reports

## Copilot Prompts

See `../../demos/lesson-01-demo-runbook-final.md` for full prompt library.
