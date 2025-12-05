# Repository Settings & Configuration

This document outlines the recommended settings for the GitHub repository.

## Repository Topics

Add these topics to improve discoverability. Go to **Settings > General > Topics** or click "About" on the repo homepage.

### Recommended Topics (copy-paste ready)

```
github-copilot
cybersecurity
security
devsecops
vulnerability-detection
secure-coding
owasp
sql-injection
xss
penetration-testing
sast
dast
compliance
nist
cis-benchmarks
zero-trust
threat-modeling
security-automation
incident-response
infrastructure-as-code
video-course
training
```

### Topic Categories

| Category | Topics |
|----------|--------|
| AI/Copilot | `github-copilot`, `ai-assisted-development`, `copilot-chat` |
| Security | `cybersecurity`, `security`, `devsecops`, `secure-coding`, `appsec` |
| Vulnerabilities | `owasp`, `vulnerability-detection`, `sql-injection`, `xss`, `penetration-testing` |
| Testing | `sast`, `dast`, `security-testing`, `fuzz-testing` |
| Compliance | `compliance`, `nist`, `cis-benchmarks`, `stig`, `security-compliance` |
| Architecture | `zero-trust`, `threat-modeling`, `security-architecture` |
| Automation | `security-automation`, `incident-response`, `infrastructure-as-code` |
| Content Type | `video-course`, `training`, `tutorial`, `educational` |

## Labels

Labels are defined in `.github/labels.yml`. To sync labels:

```bash
# Using github-label-sync
npx github-label-sync --access-token $GITHUB_TOKEN --labels .github/labels.yml timothywarner-org/github-security-testbed
```

## Repository Description

**Suggested description:**
> Hands-on demo repository for "GitHub Copilot for Cybersecurity Specialists" video course - vulnerability detection, security protocols, automated testing, and compliance automation.

## Social Preview Image

Consider adding a custom social preview image (1280x640 recommended) that includes:
- Course title
- Key topics (Copilot, Security, DevSecOps)
- Professional security-themed design

Upload at: **Settings > General > Social preview**

## Branch Protection (Optional)

For the main branch, consider enabling:
- Require pull request reviews before merging
- Require status checks to pass
- Include administrators in restrictions

## Security Settings

- Enable Dependabot alerts
- Enable Dependabot security updates
- Enable secret scanning
- Enable push protection for secrets
