# Lesson 05: Compliance, Incident Response, and IaC Security Labs

This directory contains lab files for **MS Press GitHub Copilot for Cybersecurity Professionals - Lesson 05**.

## Overview

These lab files demonstrate automated compliance checking, STIG remediation, and incident response workflows using PowerShell, Azure services, and infrastructure-as-code principles.

**Key Learning Objectives:**
- Automate CIS benchmark compliance verification
- Implement STIG remediation with PowerShell DSC
- Build incident response playbooks with automated containment
- Enable continuous compliance validation

## Directory Structure

```
lesson-05/
├── compliance/              # CIS benchmark audit scripts
│   ├── Audit-CIS-AzureSQL.ps1
│   ├── Audit-CIS-AzureStorage.ps1
│   └── compliance-report-template.json
├── stig/                    # DISA STIG remediation scripts
│   ├── Remediate-STIG-WindowsServer.ps1
│   ├── Test-STIG-Compliance.ps1
│   └── LCM-Config.ps1
├── ir-playbooks/            # Incident response automation
│   ├── Ransomware-IR-Playbook.ps1
│   ├── IR-KQL-Queries.kql
│   └── Azure-Automation-Webhook.ps1
└── README.md                # This file
```

---

## Lab 1: CIS Benchmark Compliance Auditing

**Directory:** `compliance/`

### Files

#### `Audit-CIS-AzureSQL.ps1`
PowerShell script to audit Azure SQL Database resources against CIS Microsoft Azure Foundations Benchmark.

**CIS Controls Checked:**
- CIS 4.8: Transparent Data Encryption (TDE) enabled
- CIS 4.9: Azure Active Directory authentication configured
- CIS 4.11: Firewall rules do not allow 0.0.0.0/0 (ALLOW ALL)
- CIS 4.12: Audit logging enabled

**Usage:**
```powershell
# Run compliance audit
.\Audit-CIS-AzureSQL.ps1 -SubscriptionId "YOUR_SUBSCRIPTION_ID" -Verbose

# Export results to JSON
.\Audit-CIS-AzureSQL.ps1 -SubscriptionId "YOUR_SUBSCRIPTION_ID" -ExportFormat JSON -OutputFile "compliance-report.json"

# Export results to CSV
.\Audit-CIS-AzureSQL.ps1 -SubscriptionId "YOUR_SUBSCRIPTION_ID" -ExportFormat CSV -OutputFile "compliance-report.csv"
```

**Prerequisites:**
```powershell
Install-Module -Name Az.Sql -Force
Install-Module -Name Az.Accounts -Force
Connect-AzAccount
```

#### `Audit-CIS-AzureStorage.ps1`
PowerShell script to audit Azure Storage Accounts against CIS benchmarks.

**CIS Controls Checked:**
- CIS 3.1: Secure transfer required (HTTPS only)
- CIS 3.2: Storage account encryption enabled
- CIS 3.7: Public network access disabled
- CIS 3.8: Blob soft delete enabled
- CIS 3.9: Storage account firewall configured

**Usage:**
```powershell
.\Audit-CIS-AzureStorage.ps1 -SubscriptionId "YOUR_SUBSCRIPTION_ID" -Verbose
```

#### `compliance-report-template.json`
Sample compliance report structure showing:
- Scan metadata
- Summary statistics (pass/fail/warning counts)
- Detailed findings with remediation commands
- Compliance percentage calculation

**Use this template to:**
- Understand report format for automation
- Build dashboards in Power BI or Grafana
- Integrate with ticketing systems (Jira, ServiceNow)

---

## Lab 2: STIG Remediation Automation

**Directory:** `stig/`

### Files

#### `Remediate-STIG-WindowsServer.ps1`
PowerShell DSC configuration to remediate Windows Server 2022 STIG findings.

**STIG Controls Remediated:**
- **V-93075** (CAT I): Enable Windows Defender Antimalware Service
- **V-93089** (CAT I): Enable Windows Firewall (all profiles)
- **V-93127** (CAT II): Minimum password length = 14 characters
- **V-93145** (CAT II): Account lockout duration = 30 minutes
- **V-93147** (CAT II): Password history = 24 passwords

**Usage:**
```powershell
# Validation only (no changes applied)
.\Remediate-STIG-WindowsServer.ps1 -ComputerName 'SERVER01' -ValidateOnly

# Generate DSC configuration (preview)
.\Remediate-STIG-WindowsServer.ps1 -ComputerName 'SERVER01'

# Apply STIG remediation
.\Remediate-STIG-WindowsServer.ps1 -ComputerName 'SERVER01' -ApplyRemediation
```

**Prerequisites:**
```powershell
Install-Module -Name SecurityPolicyDsc -Force
Install-Module -Name ComputerManagementDsc -Force
```

#### `Test-STIG-Compliance.ps1`
Pester tests for STIG compliance validation.

**Usage:**
```powershell
# Run all STIG compliance tests
Invoke-Pester -Path .\Test-STIG-Compliance.ps1

# Run specific test categories
Invoke-Pester -Path .\Test-STIG-Compliance.ps1 -Tag 'CAT-I'
Invoke-Pester -Path .\Test-STIG-Compliance.ps1 -Tag 'Security'

# Generate compliance report
Invoke-Pester -Path .\Test-STIG-Compliance.ps1 -OutputFormat NUnitXml -OutputFile 'STIG-Compliance-Report.xml'
```

**Prerequisites:**
```powershell
Install-Module -Name Pester -MinimumVersion 5.0 -Force
```

#### `LCM-Config.ps1`
Configure PowerShell DSC Local Configuration Manager for continuous compliance.

**Features:**
- Monitors STIG compliance every 15 minutes
- Auto-corrects configuration drift
- Maintains 30 days of audit history
- Supports both Push and Pull modes

**Usage:**
```powershell
# Configure LCM in Push mode (standalone server)
.\LCM-Config.ps1 -Mode Push

# Configure LCM in Pull mode (centralized DSC server)
.\LCM-Config.ps1 -Mode Pull -PullServerURL 'https://dsc.contoso.com/PSDscPullServer.svc' -RegistrationKey 'YOUR_KEY'

# Verify LCM configuration
Get-DscLocalConfigurationManager

# Check current compliance status
Get-DscConfigurationStatus
```

---

## Lab 3: Incident Response Automation

**Directory:** `ir-playbooks/`

### Files

#### `Ransomware-IR-Playbook.ps1`
Automated incident response playbook for ransomware detection and containment.

**IR Phases:**
1. **Detection & Validation** (automated)
   - Query Log Analytics for suspicious account creation
   - Identify file encryption patterns
   - Cross-reference with threat intelligence

2. **Containment** (semi-automated, requires approval)
   - Isolate affected VM (network disconnection)
   - Terminate suspicious processes
   - Revoke active sessions

3. **Eradication** (automated)
   - Remove suspicious user accounts
   - Delete persistence mechanisms
   - Remove malware files

5. **Evidence Collection** (automated)
   - Export Windows Event Logs
   - Calculate file hashes
   - Archive evidence with cryptographic integrity

**Usage:**
```powershell
# Detection phase only (no containment)
.\Ransomware-IR-Playbook.ps1 -VirtualMachineName 'vm-prod-01' -ResourceGroupName 'prod-rg' -SubscriptionId 'YOUR_SUB_ID'

# Execute containment (with manual approval)
.\Ransomware-IR-Playbook.ps1 -VirtualMachineName 'vm-prod-01' -ResourceGroupName 'prod-rg' -SubscriptionId 'YOUR_SUB_ID' -ExecuteContainment

# Fully automated (skip approval - USE WITH CAUTION)
.\Ransomware-IR-Playbook.ps1 -VirtualMachineName 'vm-prod-01' -ResourceGroupName 'prod-rg' -SubscriptionId 'YOUR_SUB_ID' -ExecuteContainment -SkipApproval
```

**Prerequisites:**
```powershell
Install-Module -Name Az.Compute -Force
Install-Module -Name Az.Network -Force
Install-Module -Name Az.OperationalInsights -Force
```

#### `IR-KQL-Queries.kql`
Kusto Query Language (KQL) queries for threat hunting in Azure Log Analytics / Azure Sentinel.

**Queries Included:**
1. Suspicious account creation
2. File encryption activity detection
3. Suspicious PowerShell execution
4. Backup deletion (ransomware pre-attack)
5. Mass file modification
6. Lateral movement detection
7. Persistence mechanisms
8. Ransomware note detection
9. Network connections to suspicious IPs
10. Combined ransomware indicators
11. Attack timeline reconstruction
12. Post-remediation validation

**Usage:**
1. Open Azure Portal > Log Analytics Workspace
2. Navigate to Logs
3. Copy/paste queries from `IR-KQL-Queries.kql`
4. Customize time ranges and thresholds
5. Save as Sentinel detection rules

#### `Azure-Automation-Webhook.ps1`
Configure Azure Automation infrastructure for automated incident response.

**Features:**
- Creates Azure Automation account
- Imports IR playbook as runbook
- Creates webhook for Azure Sentinel integration
- Configures alert actions to trigger playbook

**Usage:**
```powershell
# Setup Azure Automation webhook
.\Azure-Automation-Webhook.ps1 -ResourceGroupName 'security-automation-rg' `
                                -AutomationAccountName 'ir-automation' `
                                -Location 'eastus' `
                                -RunbookPath '.\Ransomware-IR-Playbook.ps1'

# Test webhook
Invoke-RestMethod -Uri $WebhookURI -Method Post -Body $TestPayload -ContentType 'application/json'
```

**Prerequisites:**
```powershell
Install-Module -Name Az.Automation -Force
Install-Module -Name Az.Resources -Force
```

---

## Integration Scenarios

### Scenario 1: Weekly Compliance Scanning (GitHub Actions)

Create `.github/workflows/compliance-scan.yml`:

```yaml
name: Weekly CIS Compliance Audit

on:
  schedule:
    - cron: '0 6 * * MON'  # Every Monday at 6 AM UTC
  workflow_dispatch:

jobs:
  audit:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3

      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Run CIS Compliance Audit
        shell: pwsh
        run: |
          ./labs/lesson-05/compliance/Audit-CIS-AzureSQL.ps1 `
            -SubscriptionId ${{ secrets.AZURE_SUBSCRIPTION_ID }} `
            -ExportFormat JSON `
            -OutputFile compliance-report.json

      - name: Upload Compliance Report
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance-report.json

      - name: Create Issue on Failure
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Compliance Audit Failed - ' + new Date().toISOString().split('T')[0],
              labels: ['compliance', 'security']
            })
```

### Scenario 2: Azure Sentinel Integration

1. Deploy Azure Automation webhook
2. Create Azure Sentinel automation rule:
   - **Trigger:** Incident created
   - **Condition:** Severity = High/Critical, Tags contain "Ransomware"
   - **Action:** Run playbook (Ransomware-IR-Playbook)

3. Test with simulated alert:
   - Create test incident in Sentinel
   - Verify webhook triggers playbook
   - Review runbook execution logs

### Scenario 3: Continuous STIG Compliance

1. Apply STIG remediation: `.\Remediate-STIG-WindowsServer.ps1 -ApplyRemediation`
2. Configure LCM: `.\LCM-Config.ps1 -Mode Push`
3. Schedule Pester tests (Windows Task Scheduler):
   ```powershell
   $Trigger = New-ScheduledTaskTrigger -Daily -At 2am
   $Action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument '-File C:\Labs\lesson-05\stig\Test-STIG-Compliance.ps1'
   Register-ScheduledTask -TaskName 'STIG-Compliance-Check' -Trigger $Trigger -Action $Action
   ```

---

## Best Practices

### Compliance Automation
- Run CIS audits weekly (minimum)
- Export reports to version control (audit trail)
- Integrate with ticketing systems for remediation tracking
- Set compliance thresholds (e.g., 95% minimum)

### STIG Remediation
- Always validate before applying changes
- Test in non-production environment first
- Maintain rollback procedures
- Document exceptions (risk acceptance)

### Incident Response
- Practice tabletop exercises quarterly
- Keep playbooks updated with latest TTPs
- Require human approval for containment actions
- Preserve evidence before eradication

### Security Considerations
- Use managed identities for Azure authentication (no hardcoded credentials)
- Encrypt compliance reports at rest and in transit
- Limit webhook access with IP whitelisting
- Rotate webhook URLs annually

---

## Troubleshooting

### CIS Audit Fails to Connect to Azure
```powershell
# Verify authentication
Connect-AzAccount
Get-AzContext

# Set correct subscription
Set-AzContext -SubscriptionId "YOUR_SUBSCRIPTION_ID"
```

### DSC Configuration Fails to Apply
```powershell
# Check LCM status
Get-DscLocalConfigurationManager

# View recent DSC operations
Get-DscConfigurationStatus

# Test configuration manually
Test-DscConfiguration -Verbose
```

### Webhook Returns 404 Error
- Verify webhook is enabled: `Get-AzAutomationWebhook`
- Check webhook expiry date
- Ensure runbook is published: `Publish-AzAutomationRunbook`

---

## Additional Resources

- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [DISA STIG Windows Server 2022](https://public.cyber.mil/stigs/)
- [Azure Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
- [PowerShell DSC Documentation](https://docs.microsoft.com/powershell/dsc/)
- [Kusto Query Language Reference](https://docs.microsoft.com/azure/data-explorer/kusto/query/)

---

## Demo Flow (Lesson 05)

**Demo 1: IaC Security Templates (10 min)**
- Show misconfigured Azure SQL (TerraGoat example)
- Generate hardened Terraform module with Copilot
- Validate with `terraform validate` and `checkov`

**Demo 2: CIS Benchmark Verification (10 min)**
- Run `Audit-CIS-AzureSQL.ps1` against production subscription
- Review compliance report (75% compliant)
- Show specific remediation commands
- Schedule weekly automation (GitHub Actions)

**Demo 3: STIG Remediation (10 min)**
- Run `Test-STIG-Compliance.ps1` (pre-remediation: 85% compliant)
- Apply `Remediate-STIG-WindowsServer.ps1 -ApplyRemediation`
- Run `Test-STIG-Compliance.ps1` (post-remediation: 97.8% compliant)
- Configure `LCM-Config.ps1` for continuous validation

**Demo 4: Incident Response Playbook (10 min)**
- Show Azure Sentinel ransomware alert
- Execute `Ransomware-IR-Playbook.ps1` (detection phase)
- Review findings (suspicious account, file encryption, PowerShell)
- Execute containment (with approval)
- Review evidence collection and incident report

---

**Author:** MS Press - GitHub Copilot for Cybersecurity Professionals
**Course:** Lesson 05 - Compliance, Incident Response, and IaC Security
**Version:** 1.0
**Last Updated:** 2025-11-30
