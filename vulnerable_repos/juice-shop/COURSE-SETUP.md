# MS Press GitHub Copilot for Cybersecurity Professionals - Course Setup

This guide walks through setting up your environment for the course demos and labs.

## Prerequisites

### Required Software

| Tool | Version | Purpose |
|------|---------|---------|
| VS Code | Latest | Primary IDE |
| Node.js | 20.x LTS | Juice Shop runtime |
| Git | Latest | Version control |
| Azure CLI | Latest | Azure deployments |
| Terraform | 1.5+ | IaC demos |
| Python | 3.11+ | Security scripts |

### Required VS Code Extensions

Install via Extensions panel or command line:

```bash
code --install-extension github.copilot
code --install-extension github.copilot-chat
code --install-extension github.vscode-github-actions
code --install-extension hashicorp.terraform
code --install-extension bridgecrew.checkov
code --install-extension semgrep.semgrep
```

### Required Accounts

- **GitHub** with Copilot subscription (Individual, Business, or Enterprise)
- **Azure** subscription (free tier works for demos)
- **GitHub Advanced Security** enabled on repository

## Quick Start

### 1. Clone and Install

```bash
git clone https://github.com/YOUR-ORG/juice-shop.git
cd juice-shop
npm install
```

### 2. Open Workspace

```bash
code juice-shop-security-course.code-workspace
```

### 3. Verify Juice Shop Runs

```bash
npm run serve:dev
# Access at http://localhost:3000
```

### 4. Verify Copilot

- Open any `.ts` file
- Type a comment like `// function to validate email`
- Copilot should suggest completion

### 5. Enable GHAS (GitHub Advanced Security)

```bash
# Via GitHub CLI
gh api repos/OWNER/REPO -X PATCH \
  -f security_and_analysis.advanced_security.status=enabled \
  -f security_and_analysis.secret_scanning.status=enabled \
  -f security_and_analysis.secret_scanning_push_protection.status=enabled
```

Or via GitHub UI: Settings → Security → Enable all GHAS features

## Lesson-Specific Setup

### Lesson 01: Vulnerability Detection

No additional setup required. Uses main Juice Shop codebase.

```bash
npm run serve:dev
```

### Lesson 02: Security Protocols

```bash
# Azure CLI login
az login
az account set --subscription "YOUR_SUBSCRIPTION"

# Terraform setup
cd iac/juice-shop-insecure
terraform init
```

### Lesson 03: Automated Testing

```bash
# Python environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install pytest pytest-cov semgrep

# Verify GHAS workflows
gh workflow list
```

### Lesson 04: Code Review & Auditing

```bash
# Install Semgrep
pip install semgrep

# Install GitHub CLI
# macOS: brew install gh
# Windows: winget install GitHub.cli

gh auth login
```

### Lesson 05: Compliance & IaC

```bash
# Azure setup
az login

# Terraform for both configs
cd iac/juice-shop-insecure && terraform init
cd ../juice-shop-hardened && terraform init

# Checkov for IaC scanning
pip install checkov

# PowerShell 7+ for STIG demos
pwsh --version
```

## Directory Structure

```
juice-shop/
├── demos/                    # Demo runbooks (lesson-01 through 05)
├── labs/                     # Lab exercises by lesson
│   ├── lesson-01/
│   ├── lesson-02/
│   ├── lesson-03/
│   ├── lesson-04/
│   └── lesson-05/
├── iac/                      # Infrastructure as Code
│   ├── juice-shop-insecure/  # Vulnerable baseline
│   └── juice-shop-hardened/  # Secure configuration
├── scripts/                  # GHAS and compliance scripts
├── routes/                   # Backend vulnerabilities
├── frontend/                 # Angular application
└── juice-shop-security-course.code-workspace
```

## Troubleshooting

### Copilot Not Suggesting

1. Verify authentication: Click Copilot icon in status bar
2. Check subscription: `gh copilot --version`
3. Restart VS Code

### GHAS Not Scanning

1. Verify enabled: Settings → Security → Code scanning
2. Check workflow runs: Actions tab
3. Manual trigger: `gh workflow run codeql-analysis.yml`

### Terraform Errors

1. Verify Azure login: `az account show`
2. Check provider version: `terraform providers`
3. Re-initialize: `terraform init -upgrade`

### Node.js Issues

1. Verify version: `node --version` (should be 20.x)
2. Clear cache: `npm cache clean --force`
3. Reinstall: `rm -rf node_modules && npm install`

## Recording Checklist

Before each lesson recording:

- [ ] Fresh terminal (clear history)
- [ ] VS Code with workspace open
- [ ] Copilot authenticated and active
- [ ] Juice Shop running on localhost:3000
- [ ] Azure CLI authenticated
- [ ] Screen recording configured
- [ ] Notifications disabled
- [ ] Font size readable (14-16pt)

## Support

- Course repo issues: Create GitHub issue
- Juice Shop docs: https://pwning.owasp-juice.shop
- Copilot docs: https://docs.github.com/copilot
