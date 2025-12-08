<#
.SYNOPSIS
    Configure Azure Automation webhook for incident response playbook integration.

.DESCRIPTION
    Sets up Azure Automation infrastructure for automated incident response:
    - Creates Azure Automation account
    - Imports IR playbook as runbook
    - Creates webhook for Azure Sentinel integration
    - Configures alert actions to trigger playbook

    When Azure Sentinel detects a high-severity alert (e.g., ransomware indicators),
    it triggers the webhook, which automatically executes the incident response playbook.

.PARAMETER ResourceGroupName
    Resource group for Azure Automation account.

.PARAMETER AutomationAccountName
    Name of the Azure Automation account.

.PARAMETER Location
    Azure region for deployment.

.PARAMETER RunbookPath
    Path to the incident response playbook script.

.PARAMETER WebhookName
    Name for the webhook (used by Azure Sentinel).

.EXAMPLE
    .\Azure-Automation-Webhook.ps1 -ResourceGroupName 'security-automation-rg' -AutomationAccountName 'ir-automation' -Location 'eastus' -RunbookPath '.\Ransomware-IR-Playbook.ps1'

.NOTES
    Author: MS Press - GitHub Copilot for Cybersecurity Professionals
    Lesson: 05 - Incident Response Automation
    Version: 1.0
    Requires: Az.Automation, Az.Resources modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,

    [Parameter(Mandatory = $true)]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [string]$RunbookPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Ransomware-IR-Playbook.ps1'),

    [Parameter(Mandatory = $false)]
    [string]$WebhookName = 'Sentinel-Ransomware-Alert'
)

#Requires -Modules Az.Automation, Az.Resources

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AZURE AUTOMATION WEBHOOK SETUP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Resource Group:       $ResourceGroupName"
Write-Host "Automation Account:   $AutomationAccountName"
Write-Host "Location:             $Location"
Write-Host "Runbook Path:         $RunbookPath"
Write-Host "Webhook Name:         $WebhookName"
Write-Host ""

# Verify runbook file exists
if (-not (Test-Path $RunbookPath)) {
    Write-Error "Runbook file not found: $RunbookPath"
    exit 1
}

# =======================
# Step 1: Create Resource Group
# =======================

Write-Host "[Step 1/6] Creating Resource Group..." -ForegroundColor Yellow

try {
    $RG = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue

    if (-not $RG) {
        $RG = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
        Write-Host "[OK] Resource group created: $ResourceGroupName" -ForegroundColor Green
    }
    else {
        Write-Host "[OK] Resource group already exists: $ResourceGroupName" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to create resource group: $($_.Exception.Message)"
    exit 1
}

# =======================
# Step 2: Create Automation Account
# =======================

Write-Host "`n[Step 2/6] Creating Azure Automation Account..." -ForegroundColor Yellow

try {
    $AutomationAccount = Get-AzAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue

    if (-not $AutomationAccount) {
        $AutomationAccount = New-AzAutomationAccount -ResourceGroupName $ResourceGroupName `
                                                      -Name $AutomationAccountName `
                                                      -Location $Location `
                                                      -Plan 'Basic'

        Write-Host "[OK] Automation account created: $AutomationAccountName" -ForegroundColor Green
    }
    else {
        Write-Host "[OK] Automation account already exists: $AutomationAccountName" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to create automation account: $($_.Exception.Message)"
    exit 1
}

# =======================
# Step 3: Import Required Modules
# =======================

Write-Host "`n[Step 3/6] Importing required PowerShell modules..." -ForegroundColor Yellow

$RequiredModules = @(
    @{ Name = 'Az.Accounts'; Version = '2.10.0' },
    @{ Name = 'Az.Compute'; Version = '5.0.0' },
    @{ Name = 'Az.Network'; Version = '5.0.0' },
    @{ Name = 'Az.OperationalInsights'; Version = '3.0.0' }
)

foreach ($Module in $RequiredModules) {
    try {
        $ExistingModule = Get-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                                   -AutomationAccountName $AutomationAccountName `
                                                   -Name $Module.Name `
                                                   -ErrorAction SilentlyContinue

        if (-not $ExistingModule) {
            Write-Host "  Importing module: $($Module.Name) v$($Module.Version)..." -ForegroundColor Gray

            $ModuleUri = "https://www.powershellgallery.com/api/v2/package/$($Module.Name)/$($Module.Version)"

            New-AzAutomationModule -ResourceGroupName $ResourceGroupName `
                                   -AutomationAccountName $AutomationAccountName `
                                   -Name $Module.Name `
                                   -ContentLinkUri $ModuleUri | Out-Null

            Write-Host "[OK] Module imported: $($Module.Name)" -ForegroundColor Green
        }
        else {
            Write-Host "[OK] Module already imported: $($Module.Name)" -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Failed to import module $($Module.Name): $($_.Exception.Message)"
    }
}

# =======================
# Step 4: Import IR Playbook as Runbook
# =======================

Write-Host "`n[Step 4/6] Importing incident response playbook as runbook..." -ForegroundColor Yellow

$RunbookName = 'Ransomware-IR-Playbook'

try {
    $Runbook = Get-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                                        -AutomationAccountName $AutomationAccountName `
                                        -Name $RunbookName `
                                        -ErrorAction SilentlyContinue

    if (-not $Runbook) {
        Import-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                                    -AutomationAccountName $AutomationAccountName `
                                    -Path $RunbookPath `
                                    -Name $RunbookName `
                                    -Type PowerShell `
                                    -Published | Out-Null

        Write-Host "[OK] Runbook imported: $RunbookName" -ForegroundColor Green
    }
    else {
        Write-Host "[OK] Runbook already exists: $RunbookName" -ForegroundColor Green
    }

    # Publish the runbook
    Publish-AzAutomationRunbook -ResourceGroupName $ResourceGroupName `
                                 -AutomationAccountName $AutomationAccountName `
                                 -Name $RunbookName | Out-Null

    Write-Host "[OK] Runbook published and ready for execution" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import runbook: $($_.Exception.Message)"
    exit 1
}

# =======================
# Step 5: Create Webhook
# =======================

Write-Host "`n[Step 5/6] Creating webhook for Azure Sentinel integration..." -ForegroundColor Yellow

try {
    $ExistingWebhook = Get-AzAutomationWebhook -ResourceGroupName $ResourceGroupName `
                                                 -AutomationAccountName $AutomationAccountName `
                                                 -RunbookName $RunbookName `
                                                 -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $WebhookName }

    if ($ExistingWebhook) {
        Write-Host "[WARNING] Webhook already exists: $WebhookName" -ForegroundColor Yellow
        Write-Host "[INFO] Existing webhook URI: $($ExistingWebhook.WebhookURI)" -ForegroundColor Cyan
        $WebhookURI = $ExistingWebhook.WebhookURI
    }
    else {
        # Create new webhook (expires in 1 year)
        $ExpiryDate = (Get-Date).AddYears(1)

        $Webhook = New-AzAutomationWebhook -ResourceGroupName $ResourceGroupName `
                                            -AutomationAccountName $AutomationAccountName `
                                            -RunbookName $RunbookName `
                                            -Name $WebhookName `
                                            -IsEnabled $true `
                                            -ExpiryTime $ExpiryDate `
                                            -Force

        $WebhookURI = $Webhook.WebhookURI

        Write-Host "[OK] Webhook created: $WebhookName" -ForegroundColor Green
        Write-Host "[IMPORTANT] Save this webhook URI - it will not be shown again!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Webhook URI:" -ForegroundColor Cyan
        Write-Host $WebhookURI -ForegroundColor White
        Write-Host ""
        Write-Host "Expiry Date: $ExpiryDate" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed to create webhook: $($_.Exception.Message)"
    exit 1
}

# =======================
# Step 6: Configure Azure Sentinel Alert Action
# =======================

Write-Host "`n[Step 6/6] Configuring Azure Sentinel alert action..." -ForegroundColor Yellow

Write-Host @"

To integrate this webhook with Azure Sentinel:

1. Navigate to Azure Sentinel in the Azure Portal
2. Go to: Configuration > Automation
3. Click: + Create > Automation rule
4. Configure:
   - Name: Ransomware IR Playbook Trigger
   - Trigger: When incident is created
   - Conditions:
     * Severity: High or Critical
     * Incident tags contains: Ransomware
   - Actions:
     * Run playbook: $RunbookName
     * Webhook URI: $WebhookURI

5. Save the automation rule

Alternative: Use Logic Apps for more complex workflows
- Create a Logic App with HTTP trigger
- HTTP POST URL: $WebhookURI
- Configure conditional logic based on alert severity
- Call webhook when conditions are met

"@ -ForegroundColor Cyan

# Save configuration to file
$ConfigOutput = @{
    ResourceGroup       = $ResourceGroupName
    AutomationAccount   = $AutomationAccountName
    RunbookName         = $RunbookName
    WebhookName         = $WebhookName
    WebhookURI          = $WebhookURI
    WebhookExpiry       = (Get-Date).AddYears(1).ToString('yyyy-MM-dd')
    CreatedDate         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

$ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'Webhook-Configuration.json'
$ConfigOutput | ConvertTo-Json | Out-File -FilePath $ConfigPath -Encoding UTF8

Write-Host "`n[OK] Configuration saved to: $ConfigPath" -ForegroundColor Green

# =======================
# Test Webhook
# =======================

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "WEBHOOK TESTING" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

Write-Host "`nWould you like to test the webhook? (Y/N): " -ForegroundColor Yellow -NoNewline
$TestWebhook = Read-Host

if ($TestWebhook -eq 'Y' -or $TestWebhook -eq 'y') {
    Write-Host "`nSending test payload to webhook..." -ForegroundColor Cyan

    $TestPayload = @{
        VirtualMachineName = 'test-vm-01'
        ResourceGroupName  = 'test-rg'
        SubscriptionId     = (Get-AzContext).Subscription.Id
        IncidentId         = 'TEST-12345'
        ExecuteContainment = $false
    } | ConvertTo-Json

    try {
        $Response = Invoke-RestMethod -Uri $WebhookURI -Method Post -Body $TestPayload -ContentType 'application/json'

        Write-Host "[OK] Webhook triggered successfully" -ForegroundColor Green
        Write-Host "Job ID: $($Response.JobId)" -ForegroundColor Cyan
        Write-Host "`nMonitor job status in Azure Portal > Automation Accounts > $AutomationAccountName > Jobs"
    }
    catch {
        Write-Host "[ERROR] Webhook test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "WEBHOOK SETUP COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Automation Account:  $AutomationAccountName"
Write-Host "Runbook:             $RunbookName"
Write-Host "Webhook:             $WebhookName"
Write-Host "Status:              Active"
Write-Host "`nNext steps:"
Write-Host "  1. Configure Azure Sentinel automation rule"
Write-Host "  2. Test with simulated ransomware alert"
Write-Host "  3. Review runbook execution logs"
Write-Host "  4. Schedule quarterly tabletop exercises"
Write-Host ""
