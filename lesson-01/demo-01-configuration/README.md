# Demo 01: Configuring GitHub Copilot for Security

## Overview

This demo shows how to configure VS Code and GitHub Copilot for security-focused development. Proper configuration ensures Copilot provides security-aware suggestions by default.

## Prerequisites

- VS Code (latest stable version)
- GitHub Copilot extension installed and activated
- GitHub Copilot Chat extension installed
- Node.js 20.x LTS

## Configuration Files

### `.vscode/settings.json`

The workspace settings configure Copilot to:

1. **Enable security suggestions** - Prioritizes secure coding patterns
2. **Filter by security** - In-editor suggestions consider security implications
3. **Enable inline suggestions** - Real-time security feedback as you type

## Validation Test

Create a test file to verify your configuration is working:

```javascript
// vulnerable-pattern-test.js
// This pattern should trigger Copilot security warnings

const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId;  // Intentionally vulnerable

// Ask Copilot Chat: "Is this code vulnerable?"
// Expected: Copilot identifies SQL injection risk
```

## Copilot Chat Prompts to Test

1. **Configuration Help:**
   ```
   Help me configure VS Code workspace settings for security-focused development.
   I want Copilot to prefer parameterized queries, input validation, and secure
   defaults. Show me settings.json configuration.
   ```

2. **Vulnerability Detection:**
   ```
   Analyze this code for SQL injection vulnerabilities. Explain the attack vector
   and show me the secure alternative.
   ```

## Recommended Extensions

Install these security-focused extensions:

```bash
# GitHub Advanced Security (CodeQL integration)
code --install-extension github.vscode-codeql

# ESLint for JavaScript security rules
code --install-extension dbaeumer.vscode-eslint

# Semgrep for SAST scanning
code --install-extension semgrep.semgrep
```

## SAST Integration

### Semgrep Setup

```bash
# Install Semgrep globally
npm install -g semgrep

# Run initial security scan
semgrep --config auto .

# View results in VS Code Problems panel
```

### Ask Copilot to Interpret Results

```
How do I integrate Semgrep with my Node.js project for continuous
security scanning? Show me package.json scripts and CI/CD integration.
```

## Key Takeaways

1. **Workspace settings are version-controlled** - Team-wide secure defaults
2. **Copilot augments existing tools** - Use alongside SAST/DAST
3. **Test your configuration** - Verify Copilot catches known vulnerabilities
4. **Iterate and improve** - Refine settings based on your security needs
