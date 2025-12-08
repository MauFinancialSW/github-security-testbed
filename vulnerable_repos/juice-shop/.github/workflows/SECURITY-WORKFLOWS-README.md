# Security Workflows Documentation

This directory contains comprehensive GitHub Actions security workflows designed for the OWASP Juice Shop project, based on the MS Press GitHub Copilot for Cybersecurity Professionals course demo runbooks.

## Overview

Four automated security workflows provide continuous security validation, compliance monitoring, and secure deployment:

1. **security-scan.yml** - Comprehensive security scanning
2. **deploy-secure.yml** - CI/CD pipeline with security gates
3. **custom-security-linting.yml** - Custom Semgrep security rules
4. **weekly-compliance-digest.yml** - Automated compliance reporting

---

## 1. security-scan.yml - Comprehensive Security Scanning

**Purpose:** Multi-faceted security scanning with CodeQL SAST, dependency analysis, and secret detection.

### Triggers
- Pull requests to `master` or `develop`
- Weekly schedule: Sundays at 2 AM UTC
- Manual dispatch

### Jobs

#### CodeQL SAST Analysis
- Uses `security-extended` query pack for comprehensive vulnerability detection
- Analyzes JavaScript/TypeScript codebase
- Uploads SARIF results to GitHub Security tab
- Excludes: `data/static/codefixes`, `frontend/node_modules`, `build`, `dist`

#### npm Audit (Dependency Scanning)
- Scans both backend and frontend dependencies
- Fails build on critical/high severity CVEs
- Generates JSON audit reports for artifacts
- Threshold: Blocks on any critical or high severity vulnerability

#### Secret Scanning
- Runs Gitleaks for secret detection in commits
- Queries GitHub secret scanning alerts API
- Reports exposed credentials, API keys, tokens

#### Security Gate Check
- Consolidated validation of all security jobs
- Blocks on: npm audit failures, secret detection
- Warns on: CodeQL analysis issues (non-blocking)
- Generates summary report with vulnerability counts

### Configuration

```yaml
# Security gate thresholds
Critical/High CVEs: BLOCK (exit 1)
CodeQL findings: WARN (exit 0)
Secrets detected: BLOCK (exit 1)
```

### Outputs
- SARIF reports uploaded to Security tab
- Artifact: `npm-audit-results` (JSON)
- GitHub Step Summary with vulnerability counts

### Usage Example

```bash
# Trigger manually
gh workflow run security-scan.yml

# View latest run
gh run list --workflow=security-scan.yml --limit 1
```

---

## 2. deploy-secure.yml - Secure CI/CD Pipeline with Security Gates

**Purpose:** Multi-stage deployment pipeline with security gates that block unsafe deployments.

### Triggers
- Push to `master` or `develop`
- Manual dispatch

### Pipeline Stages

```
test → sast → dependency-scan → compliance → security-gate → deploy
```

#### Stage 1: Test (with Coverage)
- Runs unit tests and API integration tests
- Calculates test coverage percentage
- **Gate:** Fails if coverage < 85%
- Uploads coverage reports as artifacts

#### Stage 2: SAST Scan (CodeQL)
- Performs security-extended CodeQL analysis
- Queries Code Scanning API for critical/high findings
- **Gate:** Fails if critical or high severity findings exist

#### Stage 3: Dependency Scan
- Runs npm audit for critical CVEs
- Parses and displays critical vulnerabilities
- **Gate:** Fails if any critical CVE detected

#### Stage 4: Compliance Check
- Validates security configuration
- Checks for required security headers
- Generates compliance report artifact

#### Stage 5: Security Gate Decision
- Evaluates all previous stages
- Outputs: `approved`, `requires-approval`, or `blocked`
- **Blocking conditions:**
  - Test failures or coverage < 85%
  - Critical/high SAST findings
  - Critical CVEs in dependencies

#### Stage 6: Create Security Issue (on failure)
- Automatically creates GitHub issue when gate fails
- Includes detailed failure reasons
- Labels: `security`, `security-gate`, `deployment-blocked`

#### Stage 7: Deploy to Azure App Service
- **Condition:** Only runs if security gate = `approved` AND branch = `master`
- Deploys to staging slot first
- Runs smoke tests on staging
- Swaps staging to production on success
- Automatic rollback on failure (keeps production unchanged)

### Azure Configuration Required

```bash
# GitHub Secrets needed:
AZURE_WEBAPP_PUBLISH_PROFILE_STAGING  # Staging slot publish profile
AZURE_RESOURCE_GROUP                  # Azure resource group name

# Environment variables:
AZURE_WEBAPP_NAME: 'juice-shop-prod'  # Update in workflow
NODE_VERSION: '22'
COVERAGE_THRESHOLD: 85
```

### Security Gates Summary

| Gate | Threshold | Action on Failure |
|------|-----------|-------------------|
| Test Coverage | >= 85% | BLOCK deployment |
| CodeQL Findings | 0 critical/high | BLOCK deployment |
| Critical CVEs | 0 critical | BLOCK deployment |
| Smoke Tests | HTTP 200 | ROLLBACK deployment |

### Manual Approval Process

If security gate = `requires-approval`:
1. Review the created GitHub issue
2. Assess risk and business impact
3. If acceptable, manually approve deployment via GitHub Environments

### Usage Example

```bash
# Deploy to production (must be on master branch)
git checkout master
git push origin master

# View deployment status
gh run list --workflow=deploy-secure.yml --limit 1

# View deployment environment
gh api repos/$OWNER/$REPO/deployments
```

---

## 3. custom-security-linting.yml - Custom Semgrep Security Rules

**Purpose:** Enforce organization-specific security policies with custom static analysis rules.

### Triggers
- Pull requests to `master` or `develop`
- Push to `master` or `develop`
- Manual dispatch

### Custom Security Rules

The workflow creates and enforces five custom Semgrep rules tailored to OWASP Juice Shop:

#### 1. SQL Injection Detection (`juice-shop-sql-injection`)
- **Pattern:** Raw `models.sequelize.query()` without parameterization
- **Severity:** ERROR (blocks build)
- **CWE:** CWE-89
- **Recommendation:** Use parameterized queries with `replacements`

```javascript
// BAD (detected)
models.sequelize.query("SELECT * FROM users WHERE id = " + userId);

// GOOD (passes)
models.sequelize.query('SELECT * FROM users WHERE id = :id', {
  replacements: { id: userId },
  type: QueryTypes.SELECT
});
```

#### 2. Hardcoded JWT Secrets (`juice-shop-hardcoded-jwt-secret`)
- **Pattern:** Literal strings in `jwt.sign()` or `jwt.verify()`
- **Severity:** ERROR
- **CWE:** CWE-798
- **Recommendation:** Use environment variables or config

```javascript
// BAD (detected)
jwt.sign(payload, "my-secret-key", options);

// GOOD (passes)
jwt.sign(payload, process.env.JWT_SECRET, options);
```

#### 3. XSS in EJS Templates (`juice-shop-xss-unescaped-output`)
- **Pattern:** Unescaped output `<%- var %>` in EJS files
- **Severity:** WARNING
- **CWE:** CWE-79
- **Recommendation:** Use escaped output `<%= var %>`

#### 4. Weak Password Hashing (`juice-shop-weak-password-hashing`)
- **Pattern:** `crypto.createHash('md5')` or `crypto.createHash('sha1')`
- **Severity:** ERROR
- **CWE:** CWE-916
- **Recommendation:** Use bcrypt or argon2

#### 5. Path Traversal (`juice-shop-path-traversal`)
- **Pattern:** User input directly in `fs.readFile()` paths
- **Severity:** ERROR
- **CWE:** CWE-22
- **Recommendation:** Validate and sanitize paths with `path.resolve()`

### SARIF Upload
- Results uploaded to GitHub Security tab
- Category: `semgrep-custom-rules`
- Integrated with Code Scanning alerts

### Build Behavior
- **ERROR severity:** Fails build (exit 1)
- **WARNING severity:** Allows build, posts PR comment
- **NOTE severity:** Informational only

### PR Integration
- Posts detailed comment on pull requests
- Shows top 5 errors and 3 warnings
- Links to Security tab for full results

### Suppressing False Positives

```javascript
// Use nosemgrep comment to suppress false positives
// nosemgrep: juice-shop-sql-injection
models.sequelize.query(trustedQuery);
```

### Usage Example

```bash
# Run locally with Semgrep
pip install semgrep
semgrep scan --config .semgrep/ --error .

# Test on specific file
semgrep scan --config .semgrep/sql-injection.yml routes/login.ts
```

---

## 4. weekly-compliance-digest.yml - Automated Compliance Reporting

**Purpose:** Generate weekly security compliance reports from GHAS findings.

### Triggers
- Weekly schedule: Mondays at 9 AM UTC
- Manual dispatch

### Jobs

#### 1. Fetch GHAS Alerts
- Uses existing `scripts/fetch-ghas-alerts.js` if available
- Fallback: Direct GitHub API queries
- Fetches:
  - CodeQL SAST findings
  - Dependabot dependency alerts
  - Secret scanning alerts
- Outputs: Total finding count, has-findings flag

#### 2. Generate Compliance Report
- Parses GHAS alerts JSON
- Counts by severity (critical, high, medium, low)
- Counts by type (CodeQL, Dependabot, Secrets)
- Maps to OWASP Top 10 2021 categories
- Generates Markdown report with:
  - Executive summary
  - Severity breakdown table
  - Detailed critical/high findings
  - OWASP mapping
  - Recommended actions
  - Compliance status

#### 3. Create GitHub Issue (if findings exist)
- Creates issue with full compliance report
- Labels: `security`, `compliance`, `weekly-digest`
- Title: `Weekly Security Compliance Report - YYYY-MM-DD`

#### 4. Post Success Summary (if no findings)
- Posts clean status to workflow summary
- Confirms zero open security findings

### Report Structure

```markdown
# Weekly Security Compliance Report

## Executive Summary
- Vulnerability counts by severity (table)
- Findings by type (table)

## Detailed Findings
- Critical severity findings (all)
- High severity findings (top 10)

## OWASP Top 10 Mapping
- A03:2021 - Injection
- A06:2021 - Vulnerable Components
- A07:2021 - Auth Failures

## Recommended Actions
- Immediate (Critical/High)
- This Week (Medium)
- This Month (Low)

## Compliance Status
- Overall risk level
- Compliance notes
```

### Configuration

The workflow uses the existing `scripts/fetch-ghas-alerts.js` script. To customize:

```bash
# Environment variables (set in workflow or secrets)
GITHUB_OWNER: Repository owner
GITHUB_REPO: Repository name
```

### Usage Example

```bash
# Trigger manually
gh workflow run weekly-compliance-digest.yml

# View latest compliance report issue
gh issue list --label compliance --limit 1

# Download compliance report artifact
gh run download --name compliance-report
```

---

## Integration with Existing Workflows

These security workflows complement the existing Juice Shop CI/CD:

### Existing Workflows
- `ci.yml` - Main CI/CD pipeline (tests, builds, Docker)
- `codeql-analysis.yml` - CodeQL scanning
- `zap_scan.yml` - OWASP ZAP dynamic scanning

### New Security Workflows
- Extend existing CodeQL with security-extended queries
- Add dependency scanning with blocking thresholds
- Introduce security gates before deployment
- Automate compliance reporting

### Recommended Workflow Order

1. **On Pull Request:**
   ```
   ci.yml → security-scan.yml → custom-security-linting.yml
   ```

2. **On Push to master:**
   ```
   ci.yml → deploy-secure.yml (includes all security gates)
   ```

3. **Weekly Schedule:**
   ```
   weekly-compliance-digest.yml (Mondays)
   security-scan.yml (Sundays)
   ```

---

## Security Secrets Configuration

### Required Secrets

```bash
# GitHub native (already available)
GITHUB_TOKEN                           # Automatic
secrets.GITHUB_TOKEN                   # API access

# Azure deployment (add to repository secrets)
AZURE_WEBAPP_PUBLISH_PROFILE_STAGING   # Staging slot credentials
AZURE_RESOURCE_GROUP                   # Resource group name

# Optional (for enhanced reporting)
SLACK_WEBHOOK_URL                      # Slack notifications
MAIL_USERNAME                          # Email notifications
MAIL_PASSWORD                          # Email credentials
```

### Adding Secrets

```bash
# Via GitHub CLI
gh secret set AZURE_WEBAPP_PUBLISH_PROFILE_STAGING < staging-profile.xml
gh secret set AZURE_RESOURCE_GROUP -b "juice-shop-rg"

# Via GitHub UI
# Settings → Secrets and variables → Actions → New repository secret
```

---

## Monitoring and Troubleshooting

### View Workflow Status

```bash
# All security workflows
gh run list --workflow=security-scan.yml --limit 5
gh run list --workflow=deploy-secure.yml --limit 5
gh run list --workflow=custom-security-linting.yml --limit 5
gh run list --workflow=weekly-compliance-digest.yml --limit 5

# Watch live run
gh run watch <run-id>
```

### Common Issues

#### 1. npm audit fails with too many vulnerabilities
**Solution:** Review and update dependencies incrementally
```bash
npm audit fix
npm audit fix --force  # Use with caution
```

#### 2. CodeQL analysis times out
**Solution:** Increase timeout or exclude large generated files
```yaml
# In workflow
timeout-minutes: 20  # Increase from default
```

#### 3. Azure deployment fails
**Solution:** Verify publish profile and resource group
```bash
# Test Azure CLI authentication
az account show
az webapp list --resource-group $AZURE_RESOURCE_GROUP
```

#### 4. Semgrep false positives
**Solution:** Suppress with nosemgrep comments
```javascript
// nosemgrep: rule-id
const query = trustedStaticQuery;
```

### Debugging Steps

```bash
# 1. Enable debug logging
gh workflow run security-scan.yml --debug

# 2. Download workflow logs
gh run view <run-id> --log

# 3. Download artifacts
gh run download <run-id>

# 4. Re-run failed jobs
gh run rerun <run-id> --failed
```

---

## Customization Guide

### Adjusting Security Gate Thresholds

#### Test Coverage Threshold
```yaml
# deploy-secure.yml
env:
  COVERAGE_THRESHOLD: 85  # Change to desired percentage
```

#### Vulnerability Severity Thresholds
```yaml
# security-scan.yml
- name: Run npm audit
  run: npm audit --audit-level=high  # Options: critical, high, moderate, low
```

### Adding Custom Semgrep Rules

```bash
# Create new rule file
cat > .semgrep/my-custom-rule.yml << 'EOF'
rules:
  - id: my-security-check
    pattern: dangerous_function($ARG)
    message: Detected dangerous pattern
    severity: ERROR
    languages: [javascript, typescript]
EOF
```

### Modifying Report Format

Edit `weekly-compliance-digest.yml`:
```bash
# Generate custom report format
- name: Generate compliance report
  run: |
    # Add your custom logic here
    jq '.alerts[] | custom_format' ghas-alerts.json > report.md
```

---

## Best Practices

### 1. Security Gates
- Keep critical/high severity as blocking
- Allow medium/low for backlog triage
- Require manual approval for emergency deployments

### 2. Dependency Management
- Run weekly scans to catch new CVEs
- Prioritize critical CVEs with active exploits
- Test dependency updates in staging first

### 3. Compliance Reporting
- Review weekly digest issues promptly
- Track remediation progress in GitHub Projects
- Export reports for audit evidence

### 4. Custom Linting
- Test new Semgrep rules on feature branches first
- Suppress false positives with justification comments
- Review and update rules quarterly

### 5. Incident Response
- Security gate failures create issues automatically
- Triage within 24 hours for critical findings
- Document risk acceptance decisions

---

## Metrics and KPIs

### Security Posture Metrics
- **Mean Time to Remediate (MTTR):** Time from finding detection to fix deployed
- **Vulnerability Density:** Findings per 1000 lines of code
- **Security Gate Success Rate:** Percentage of deployments passing all gates
- **Coverage Trend:** Test coverage percentage over time

### Tracking in GitHub

```bash
# Count open security findings
gh api repos/$OWNER/$REPO/code-scanning/alerts?state=open --jq 'length'
gh api repos/$OWNER/$REPO/dependabot/alerts?state=open --jq 'length'

# Time to close (requires GH Projects or custom script)
gh issue list --label security --state closed --json closedAt,createdAt
```

---

## Resources

### OWASP Juice Shop
- [Companion Guide](https://pwning.owasp-juice.shop)
- [GitHub Repository](https://github.com/juice-shop/juice-shop)
- [Security Documentation](https://github.com/juice-shop/juice-shop#security)

### GitHub Security Features
- [Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [Dependabot](https://docs.github.com/en/code-security/dependabot)
- [Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)

### Security Standards
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

### Tools Documentation
- [Semgrep Rules](https://semgrep.dev/docs/writing-rules/overview/)
- [CodeQL Queries](https://codeql.github.com/docs/writing-codeql-queries/)
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit)

---

## Support and Contribution

### Getting Help
- GitHub Issues: Report workflow bugs or request features
- Discussions: Ask questions and share improvements
- Security Policy: Report security vulnerabilities via GitHub Security Advisories

### Contributing Improvements
1. Fork the repository
2. Create feature branch for workflow changes
3. Test workflows in your fork
4. Submit pull request with clear description

### Maintenance
- Review and update workflows quarterly
- Update action versions to latest stable
- Adjust thresholds based on team velocity
- Archive old compliance reports

---

**Generated with [Claude Code](https://claude.com/claude-code)**

**Course:** MS Press GitHub Copilot for Cybersecurity Professionals
**Lessons:** Based on demo runbooks 01-05
**Last Updated:** 2025-11-30
