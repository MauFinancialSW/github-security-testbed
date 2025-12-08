# Security Workflows Quick Start Guide

Get started with the new security workflows in 5 minutes.

## What Was Created

Four production-ready GitHub Actions workflows for comprehensive security automation:

```
.github/workflows/
├── security-scan.yml              (253 lines) - Comprehensive security scanning
├── deploy-secure.yml              (432 lines) - Secure CI/CD with gates
├── custom-security-linting.yml    (358 lines) - Custom Semgrep rules
└── weekly-compliance-digest.yml   (348 lines) - Automated compliance reports
```

**Total:** 1,391 lines of security automation

## Prerequisites Checklist

### Required (Already Available)
- [x] GitHub Advanced Security (GHAS) enabled
- [x] CodeQL already configured (existing codeql-analysis.yml)
- [x] Node.js project with npm
- [x] Existing scripts/fetch-ghas-alerts.js

### Optional (For Full Features)
- [ ] Azure App Service for deployment (deploy-secure.yml)
- [ ] GitHub Environments configured for production
- [ ] Azure publish profile secrets

## Quick Setup (5 Minutes)

### Step 1: Verify Workflows Are Active (1 min)

```bash
# List workflows
gh workflow list

# You should see:
# - Comprehensive Security Scan
# - Secure CI/CD Pipeline with Security Gates
# - Custom Security Linting with Semgrep
# - Weekly Compliance Digest
```

### Step 2: Test Security Scan (2 min)

```bash
# Trigger manually
gh workflow run security-scan.yml

# Watch it run
gh run watch

# View results
gh run list --workflow=security-scan.yml --limit 1
```

Expected outcome:
- CodeQL SAST analysis completes
- npm audit runs on dependencies
- Secret scanning checks
- Results appear in Security tab

### Step 3: Test Custom Linting (1 min)

```bash
# Create a test branch
git checkout -b test-security-linting

# Trigger on push
git commit --allow-empty -m "Test security linting"
git push origin test-security-linting

# View results
gh run list --workflow=custom-security-linting.yml --limit 1
```

Expected outcome:
- Semgrep creates 5 custom security rules
- Scans codebase for vulnerabilities
- Uploads SARIF to Security tab
- Fails if ERROR severity findings exist

### Step 4: Schedule Weekly Reports (1 min)

The weekly compliance digest runs automatically every Monday at 9 AM UTC. To test now:

```bash
# Trigger manually
gh workflow run weekly-compliance-digest.yml

# View latest issue
gh issue list --label compliance --limit 1
```

Expected outcome:
- Fetches all GHAS alerts
- Generates compliance report
- Creates GitHub issue with findings (if any exist)

## What Happens Automatically

### On Pull Request
```
1. security-scan.yml runs → Comprehensive SAST + dependency + secret scanning
2. custom-security-linting.yml runs → Enforces custom security rules
3. Results posted as PR comments
4. Blocks merge if ERROR severity findings
```

### On Push to master
```
1. deploy-secure.yml runs → Multi-stage security gates
2. Tests → SAST → Dependencies → Compliance → Gate Decision
3. Only deploys if ALL gates pass (or requires manual approval)
4. Creates issue on gate failure
```

### Weekly Schedule
```
1. Sunday 2 AM UTC → security-scan.yml (comprehensive scan)
2. Monday 9 AM UTC → weekly-compliance-digest.yml (report generation)
```

## Viewing Results

### Security Tab
```bash
# Open in browser
gh browse --settings security

# View Code Scanning alerts
gh browse /security/code-scanning

# View Dependabot alerts
gh browse /security/dependabot

# View Secret Scanning alerts
gh browse /security/secret-scanning
```

### GitHub Issues
```bash
# List all security issues
gh issue list --label security

# List compliance reports
gh issue list --label compliance

# List deployment blocks
gh issue list --label deployment-blocked
```

### Workflow Runs
```bash
# View all security workflow runs
gh run list --workflow=security-scan.yml
gh run list --workflow=deploy-secure.yml
gh run list --workflow=custom-security-linting.yml
gh run list --workflow=weekly-compliance-digest.yml

# Download artifacts from latest run
gh run download --name npm-audit-results
gh run download --name compliance-report
```

## Understanding Security Gates

### What Blocks Deployment?

| Condition | Result | Action |
|-----------|--------|--------|
| Test coverage < 85% | BLOCKED | Fix tests, increase coverage |
| Critical/High CVEs | BLOCKED | Update dependencies |
| Critical/High SAST | REQUIRES APPROVAL | Review findings, assess risk |
| Secrets detected | BLOCKED | Remove secrets, rotate credentials |
| Semgrep ERROR findings | BLOCKED | Fix security issues |

### Security Gate Workflow

```
Tests → SAST → Dependencies → Compliance
  ↓       ↓         ↓            ↓
  ✅      ✅        ✅           ✅  → APPROVED → Deploy
  ✅      ✅        ❌           ✅  → BLOCKED → Issue created
  ✅      ❌        ✅           ✅  → REQUIRES APPROVAL → Manual review
  ❌      -         -            -   → BLOCKED → Fix tests first
```

## Common Commands

### Manual Workflow Triggers
```bash
# Run security scan
gh workflow run security-scan.yml

# Run deployment pipeline
gh workflow run deploy-secure.yml

# Run custom linting
gh workflow run custom-security-linting.yml

# Generate compliance report
gh workflow run weekly-compliance-digest.yml
```

### Monitoring
```bash
# Watch live run
gh run watch

# View run logs
gh run view <run-id> --log

# Re-run failed jobs
gh run rerun <run-id> --failed
```

### Troubleshooting
```bash
# Check workflow syntax
gh workflow view security-scan.yml

# Enable debug logging
gh workflow run security-scan.yml --debug

# Download all artifacts
gh run download <run-id>
```

## Customization Quick Reference

### Adjust Coverage Threshold
```yaml
# File: deploy-secure.yml
env:
  COVERAGE_THRESHOLD: 85  # Change to desired percentage (e.g., 80, 90)
```

### Change Dependency Scan Sensitivity
```yaml
# File: security-scan.yml
- name: Run npm audit
  run: npm audit --audit-level=high  # Options: critical, high, moderate, low
```

### Modify Schedule
```yaml
# File: weekly-compliance-digest.yml
on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9 AM UTC
    # Change to: '0 9 * * 5' for Friday
    # Change to: '0 14 * * 1' for Monday 2 PM UTC
```

### Add Custom Semgrep Rule
```bash
# Create new rule file
cat > .semgrep/my-rule.yml << 'EOF'
rules:
  - id: my-security-check
    pattern: dangerous_function(...)
    message: Custom security check failed
    severity: ERROR
    languages: [javascript, typescript]
EOF

# Rule will be picked up automatically
```

## Azure Deployment Setup (Optional)

Only needed if using deploy-secure.yml deployment features.

### Required Secrets
```bash
# Download publish profile from Azure Portal
# Then set as secret:
gh secret set AZURE_WEBAPP_PUBLISH_PROFILE_STAGING < staging-profile.xml
gh secret set AZURE_RESOURCE_GROUP -b "your-resource-group-name"
```

### Update Workflow Variables
```yaml
# File: deploy-secure.yml
env:
  AZURE_WEBAPP_NAME: 'juice-shop-prod'  # Change to your app name
```

### Create GitHub Environment
```bash
# Via GitHub CLI
gh api repos/$OWNER/$REPO/environments/production -X PUT

# Or via UI:
# Settings → Environments → New environment → "production"
```

## Metrics Dashboard

Track security posture over time:

```bash
# Current security findings count
gh api repos/$OWNER/$REPO/code-scanning/alerts?state=open --jq 'length'
gh api repos/$OWNER/$REPO/dependabot/alerts?state=open --jq 'length'

# Workflow success rate (last 10 runs)
gh run list --workflow=security-scan.yml --limit 10 --json conclusion

# Security gate pass rate
gh run list --workflow=deploy-secure.yml --limit 10 --json conclusion
```

## Next Steps

### Week 1: Observe and Learn
- Monitor workflow runs
- Review security findings
- Understand false positives
- Adjust thresholds if needed

### Week 2: Tune and Optimize
- Suppress false positive Semgrep rules
- Adjust coverage threshold based on team velocity
- Review dependency update process
- Document exceptions

### Week 3: Integrate and Automate
- Connect to Slack for notifications
- Integrate with project management tools
- Set up automated dependency updates
- Train team on security workflows

### Month 2: Measure and Improve
- Track MTTR (Mean Time to Remediate)
- Measure vulnerability density trends
- Review security gate effectiveness
- Iterate on custom Semgrep rules

## Getting Help

### Documentation
- Full reference: `SECURITY-WORKFLOWS-README.md`
- Architecture diagrams: `WORKFLOW-DIAGRAM.md`
- OWASP Juice Shop docs: https://pwning.owasp-juice.shop

### Troubleshooting
1. Check workflow run logs: `gh run view <run-id> --log`
2. Review Security tab: `gh browse /security`
3. Search existing issues: `gh issue list --label security`
4. Create new issue: `gh issue create --label security`

### Support Resources
- GitHub Docs: https://docs.github.com/en/code-security
- Semgrep Docs: https://semgrep.dev/docs
- OWASP Resources: https://owasp.org

## Success Criteria

After 1 week, you should see:
- ✅ All workflows running successfully
- ✅ Security findings in Security tab
- ✅ Weekly compliance reports
- ✅ Security gates blocking unsafe deployments

After 1 month, you should achieve:
- ✅ 80%+ security gate pass rate
- ✅ < 24 hour MTTR for critical findings
- ✅ Zero critical/high vulnerabilities in production
- ✅ Automated security compliance

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│              Security Workflows Cheat Sheet             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Trigger All Scans:                                     │
│    gh workflow run security-scan.yml                    │
│                                                         │
│  View Security Findings:                                │
│    gh browse /security                                  │
│                                                         │
│  Check Compliance Status:                               │
│    gh issue list --label compliance                     │
│                                                         │
│  Monitor Deployments:                                   │
│    gh run list --workflow=deploy-secure.yml             │
│                                                         │
│  Download Reports:                                      │
│    gh run download --name compliance-report             │
│                                                         │
│  Emergency Override:                                    │
│    Settings → Environments → production → Approve       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

**Ready to secure your CI/CD pipeline!**

For detailed documentation, see `SECURITY-WORKFLOWS-README.md`

*Generated with [Claude Code](https://claude.com/claude-code)*
*Based on MS Press GitHub Copilot for Cybersecurity Professionals course*
