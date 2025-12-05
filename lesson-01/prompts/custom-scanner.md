# Custom Vulnerability Scanner Prompt

## Purpose
Use this prompt with GitHub Copilot to build custom security scanners for business logic vulnerabilities that generic tools miss.

## Prompt Template

```
Help me build a custom vulnerability scanner for [VULNERABILITY_TYPE] in a [APPLICATION_TYPE].

The scanner should:
1. Define target endpoints and authentication requirements
2. Implement automated testing logic
3. Detect successful exploitation
4. Generate detailed findings with severity ratings
5. Include remediation recommendations
6. Output structured reports (JSON/HTML/Markdown)

Specific requirements:
- [List specific business logic to test]
- [Authentication/authorization model details]
- [Expected behavior vs vulnerable behavior]

Provide working Node.js code with axios for HTTP requests.
```

## Scanner Templates

### IDOR Scanner Prompt
```
Build a custom IDOR vulnerability scanner for a multi-tenant SaaS API.

The scanner should:
1. Accept auth tokens for multiple tenants (A and B)
2. Attempt cross-tenant resource access using Tenant A's token on Tenant B's resources
3. Detect successful unauthorized access (200 response with data)
4. Generate findings with:
   - Affected endpoint
   - Tested resource IDs
   - Evidence (response data preview)
   - Severity rating (CRITICAL for cross-tenant access)
   - Remediation steps

Test these endpoints:
- GET /api/documents/:id
- GET /api/users/:id
- GET /api/invoices/:id
- POST /api/documents/batch-export

Provide complete Node.js implementation with axios.
```

### Race Condition Scanner Prompt
```
Generate a race condition scanner for e-commerce operations.

Test scenarios:
1. Coupon code redemption - detect if single-use codes can be reused
2. Balance withdrawal - detect if users can overdraw accounts
3. Inventory purchase - detect if items can be oversold

The scanner should:
1. Send N concurrent requests (configurable, default 50)
2. Use Promise.allSettled for parallel execution
3. Analyze results to detect:
   - Coupon: more than 1 successful redemption
   - Balance: total withdrawn > initial balance
   - Inventory: total sold > initial stock
4. Generate report with business impact estimates

Include rate limiting awareness and request timing analysis.
```

### Authentication Bypass Scanner Prompt
```
Create a scanner to test for authentication bypass vulnerabilities.

Test cases:
1. JWT algorithm confusion (none algorithm)
2. JWT secret brute force (common secrets list)
3. Session fixation
4. Password reset token predictability
5. OAuth state parameter validation
6. API key in URL vs header treatment

For each test:
- Send crafted requests
- Detect successful bypass
- Document the attack vector
- Rate severity based on impact
```

### Business Logic Scanner Prompt
```
Build a scanner for business logic vulnerabilities in a financial application.

Test for:
1. Negative quantity/amount handling
2. Integer overflow in calculations
3. Currency conversion manipulation
4. Time-of-check to time-of-use issues
5. State machine violations (e.g., approve before submit)
6. Privilege escalation via parameter manipulation

Include:
- Test case generation
- Boundary value analysis
- State transition testing
- Detailed logging of each test
```

## Scanner Architecture Template

```javascript
// Generic scanner class structure
class VulnerabilityScanner {
  constructor(config) {
    this.baseUrl = config.baseUrl;
    this.authTokens = config.authTokens;
    this.findings = [];
    this.options = {
      timeout: config.timeout || 10000,
      retries: config.retries || 3,
      concurrency: config.concurrency || 10,
      verbose: config.verbose || false
    };
  }

  // Authentication helper
  getHeaders(context) {
    // Return appropriate auth headers
  }

  // Single test execution
  async runTest(testCase) {
    // Execute test and capture result
  }

  // Finding generation
  addFinding(severity, type, details) {
    this.findings.push({
      id: `VULN-${Date.now()}`,
      severity,
      type,
      ...details,
      timestamp: new Date().toISOString()
    });
  }

  // Report generation
  generateReport() {
    return {
      metadata: { /* scan info */ },
      summary: { /* counts by severity */ },
      findings: this.findings,
      recommendations: this.getRecommendations()
    };
  }

  // Main scan orchestration
  async scan() {
    // Run all test categories
    // Generate and return report
  }
}
```

## Output Format Templates

### JSON Report
```json
{
  "metadata": {
    "scanId": "SCAN-123456",
    "timestamp": "2024-01-15T10:30:00Z",
    "target": "https://api.example.com",
    "scanner": "Custom IDOR Scanner v1.0"
  },
  "summary": {
    "totalTests": 50,
    "passed": 45,
    "failed": 5,
    "findings": {
      "critical": 2,
      "high": 2,
      "medium": 1
    }
  },
  "findings": [
    {
      "id": "VULN-001",
      "title": "Cross-tenant document access",
      "severity": "CRITICAL",
      "endpoint": "GET /api/documents/:id",
      "evidence": { /* proof of exploitation */ },
      "remediation": [ /* steps */ ],
      "references": [ /* CWE, OWASP */ ]
    }
  ]
}
```

### Markdown Report
```markdown
# Security Scan Report

## Summary
- **Target:** https://api.example.com
- **Date:** 2024-01-15
- **Critical Findings:** 2
- **High Findings:** 2

## Critical Findings

### VULN-001: Cross-tenant Document Access
**Endpoint:** GET /api/documents/:id
**Description:** User from Tenant A can access documents belonging to Tenant B

**Evidence:**
- Request: GET /api/documents/456 with Tenant A token
- Response: 200 OK with Tenant B's document data

**Remediation:**
1. Add tenant_id filter to all queries
2. Verify document ownership before returning data

---
```

## Integration Prompts

### CI/CD Integration
```
Generate a GitHub Actions workflow that:
1. Runs the custom scanner against staging environment
2. Parses JSON report
3. Fails build if critical/high findings exist
4. Posts summary as PR comment
5. Uploads full report as artifact
```

### Slack Notification
```
Add Slack webhook integration to the scanner:
1. Send alert on critical findings
2. Include finding summary and affected endpoints
3. Link to full report
4. Tag security team channel
```

### Jira Integration
```
Generate code to create Jira tickets from scan findings:
1. Map severity to Jira priority
2. Include technical details in description
3. Add remediation steps as subtasks
4. Link related CWE/OWASP references
```

## Best Practices

### Scanner Development
1. Start with manual testing to understand the vulnerability
2. Identify clear success/failure criteria
3. Handle edge cases and errors gracefully
4. Include rate limiting to avoid DoS
5. Log all requests for debugging
6. Validate findings manually before reporting

### Safe Testing
1. Only test systems you have authorization for
2. Use test/staging environments when possible
3. Avoid destructive operations (DELETE, data modification)
4. Implement kill switch for long-running scans
5. Respect rate limits and system resources
