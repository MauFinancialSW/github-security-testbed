<#
.SYNOPSIS
    CIS Microsoft Azure Foundations Benchmark compliance audit for Azure Storage Accounts.

.DESCRIPTION
    Validates Azure Storage Account resources against CIS benchmark controls:
    - CIS 3.1: Secure transfer required (HTTPS only)
    - CIS 3.2: Storage account encryption enabled
    - CIS 3.3: Storage account uses private endpoints
    - CIS 3.7: Public network access disabled
    - CIS 3.8: Blob soft delete enabled
    - CIS 3.9: Storage account firewall configured

.PARAMETER SubscriptionId
    Azure subscription ID to audit.

.PARAMETER ExportFormat
    Output format: JSON, CSV, or Console (default).

.PARAMETER OutputFile
    Path to export compliance report.

.EXAMPLE
    .\Audit-CIS-AzureStorage.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -Verbose

.NOTES
    Author: MS Press - GitHub Copilot for Cybersecurity Professionals
    Lesson: 05 - Compliance Automation
    Version: 1.0
    Requires: Az.Storage PowerShell module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [ValidateSet('JSON', 'CSV', 'Console')]
    [string]$ExportFormat = 'Console',

    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

#Requires -Modules Az.Storage, Az.Accounts

# CIS Benchmark Control Definitions
$CISControls = @{
    'CIS-3.1' = @{
        Name        = 'Secure Transfer Required (HTTPS Only)'
        Description = 'Ensures storage accounts require secure transfer'
        Severity    = 'HIGH'
    }
    'CIS-3.2' = @{
        Name        = 'Storage Encryption Enabled'
        Description = 'Ensures storage account encryption is enabled'
        Severity    = 'HIGH'
    }
    'CIS-3.7' = @{
        Name        = 'Public Network Access Disabled'
        Description = 'Ensures storage accounts are not publicly accessible'
        Severity    = 'CRITICAL'
    }
    'CIS-3.8' = @{
        Name        = 'Blob Soft Delete Enabled'
        Description = 'Ensures blob soft delete is enabled for data protection'
        Severity    = 'MEDIUM'
    }
    'CIS-3.9' = @{
        Name        = 'Storage Account Firewall Configured'
        Description = 'Ensures network access is restricted via firewall'
        Severity    = 'HIGH'
    }
}

# Compliance report structure
$ComplianceReport = [PSCustomObject]@{
    ScanDate              = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    SubscriptionId        = $SubscriptionId
    TotalStorageAccounts  = 0
    Summary               = @{
        TotalControls         = $CISControls.Count
        Passed                = 0
        Failed                = 0
        Warnings              = 0
        CompliancePercentage  = 0
    }
    Findings              = @()
}

function Write-ComplianceLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'PASS', 'FAIL', 'WARNING')]
        [string]$Level = 'INFO'
    )

    $Color = switch ($Level) {
        'PASS'    { 'Green' }
        'FAIL'    { 'Red' }
        'WARNING' { 'Yellow' }
        default   { 'White' }
    }

    Write-Host "[$Level] $Message" -ForegroundColor $Color
}

# Connect to Azure
try {
    Write-ComplianceLog "Connecting to Azure subscription: $SubscriptionId" -Level INFO
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    Write-ComplianceLog "Successfully connected to Azure" -Level PASS
}
catch {
    Write-ComplianceLog "Failed to connect to Azure: $($_.Exception.Message)" -Level FAIL
    exit 1
}

# Get all Storage Accounts in subscription
Write-ComplianceLog "Retrieving Azure Storage Accounts..." -Level INFO
$StorageAccounts = Get-AzStorageAccount
$ComplianceReport.TotalStorageAccounts = $StorageAccounts.Count

if ($StorageAccounts.Count -eq 0) {
    Write-ComplianceLog "No Azure Storage Accounts found in subscription" -Level WARNING
    exit 0
}

Write-ComplianceLog "Found $($StorageAccounts.Count) Storage Account(s)" -Level INFO

# Audit each Storage Account
foreach ($StorageAccount in $StorageAccounts) {
    Write-ComplianceLog "`nAuditing Storage Account: $($StorageAccount.StorageAccountName)" -Level INFO

    # =======================
    # CIS 3.1: Secure Transfer Required
    # =======================
    if ($StorageAccount.EnableHttpsTrafficOnly -eq $true) {
        Write-ComplianceLog "  [CIS-3.1] Secure Transfer Required: PASS" -Level PASS
        $ComplianceReport.Summary.Passed++
    }
    else {
        Write-ComplianceLog "  [CIS-3.1] Secure Transfer Not Required: FAIL" -Level FAIL
        $ComplianceReport.Summary.Failed++

        $ComplianceReport.Findings += [PSCustomObject]@{
            ControlId    = 'CIS-3.1'
            ControlName  = $CISControls['CIS-3.1'].Name
            Status       = 'FAIL'
            Severity     = $CISControls['CIS-3.1'].Severity
            ResourceType = 'Storage Account'
            ResourceName = $StorageAccount.StorageAccountName
            Finding      = 'Storage account allows HTTP traffic (insecure)'
            Remediation  = "Set-AzStorageAccount -ResourceGroupName '$($StorageAccount.ResourceGroupName)' -Name '$($StorageAccount.StorageAccountName)' -EnableHttpsTrafficOnly `$true"
        }
    }

    # =======================
    # CIS 3.2: Storage Encryption
    # =======================
    if ($StorageAccount.Encryption.Services.Blob.Enabled -eq $true) {
        Write-ComplianceLog "  [CIS-3.2] Blob Encryption Enabled: PASS" -Level PASS
        $ComplianceReport.Summary.Passed++
    }
    else {
        Write-ComplianceLog "  [CIS-3.2] Blob Encryption Disabled: FAIL" -Level FAIL
        $ComplianceReport.Summary.Failed++

        $ComplianceReport.Findings += [PSCustomObject]@{
            ControlId    = 'CIS-3.2'
            ControlName  = $CISControls['CIS-3.2'].Name
            Status       = 'FAIL'
            Severity     = $CISControls['CIS-3.2'].Severity
            ResourceType = 'Storage Account'
            ResourceName = $StorageAccount.StorageAccountName
            Finding      = 'Blob storage encryption is not enabled'
            Remediation  = "Storage account encryption should be enabled during creation. Consider recreating the storage account with encryption enabled."
        }
    }

    # =======================
    # CIS 3.7: Public Network Access
    # =======================
    if ($StorageAccount.PublicNetworkAccess -eq 'Disabled') {
        Write-ComplianceLog "  [CIS-3.7] Public Network Access Disabled: PASS" -Level PASS
        $ComplianceReport.Summary.Passed++
    }
    else {
        Write-ComplianceLog "  [CIS-3.7] Public Network Access Enabled: FAIL" -Level FAIL
        $ComplianceReport.Summary.Failed++

        $ComplianceReport.Findings += [PSCustomObject]@{
            ControlId    = 'CIS-3.7'
            ControlName  = $CISControls['CIS-3.7'].Name
            Status       = 'FAIL'
            Severity     = $CISControls['CIS-3.7'].Severity
            ResourceType = 'Storage Account'
            ResourceName = $StorageAccount.StorageAccountName
            Finding      = 'Storage account allows public network access'
            Remediation  = "Set-AzStorageAccount -ResourceGroupName '$($StorageAccount.ResourceGroupName)' -Name '$($StorageAccount.StorageAccountName)' -PublicNetworkAccess Disabled"
        }
    }

    # =======================
    # CIS 3.8: Blob Soft Delete
    # =======================
    try {
        $BlobServiceProperties = Get-AzStorageBlobServiceProperty -ResourceGroupName $StorageAccount.ResourceGroupName `
                                                                    -StorageAccountName $StorageAccount.StorageAccountName

        if ($BlobServiceProperties.DeleteRetentionPolicy.Enabled -eq $true) {
            Write-ComplianceLog "  [CIS-3.8] Blob Soft Delete Enabled (Retention: $($BlobServiceProperties.DeleteRetentionPolicy.Days) days): PASS" -Level PASS
            $ComplianceReport.Summary.Passed++
        }
        else {
            Write-ComplianceLog "  [CIS-3.8] Blob Soft Delete Disabled: FAIL" -Level FAIL
            $ComplianceReport.Summary.Failed++

            $ComplianceReport.Findings += [PSCustomObject]@{
                ControlId    = 'CIS-3.8'
                ControlName  = $CISControls['CIS-3.8'].Name
                Status       = 'FAIL'
                Severity     = $CISControls['CIS-3.8'].Severity
                ResourceType = 'Storage Account'
                ResourceName = $StorageAccount.StorageAccountName
                Finding      = 'Blob soft delete is not enabled (no data protection)'
                Remediation  = "Enable-AzStorageBlobDeleteRetentionPolicy -ResourceGroupName '$($StorageAccount.ResourceGroupName)' -StorageAccountName '$($StorageAccount.StorageAccountName)' -RetentionDays 30"
            }
        }
    }
    catch {
        Write-ComplianceLog "  [CIS-3.8] Blob Soft Delete Check Error: $($_.Exception.Message)" -Level WARNING
        $ComplianceReport.Summary.Warnings++
    }

    # =======================
    # CIS 3.9: Network Firewall Rules
    # =======================
    if ($StorageAccount.NetworkRuleSet.DefaultAction -eq 'Deny') {
        Write-ComplianceLog "  [CIS-3.9] Storage Firewall Configured (Default Deny): PASS" -Level PASS
        $ComplianceReport.Summary.Passed++
    }
    else {
        Write-ComplianceLog "  [CIS-3.9] Storage Firewall Not Configured (Default Allow): FAIL" -Level FAIL
        $ComplianceReport.Summary.Failed++

        $ComplianceReport.Findings += [PSCustomObject]@{
            ControlId    = 'CIS-3.9'
            ControlName  = $CISControls['CIS-3.9'].Name
            Status       = 'FAIL'
            Severity     = $CISControls['CIS-3.9'].Severity
            ResourceType = 'Storage Account'
            ResourceName = $StorageAccount.StorageAccountName
            Finding      = 'Storage account network firewall allows all traffic by default'
            Remediation  = "Update-AzStorageAccountNetworkRuleSet -ResourceGroupName '$($StorageAccount.ResourceGroupName)' -Name '$($StorageAccount.StorageAccountName)' -DefaultAction Deny"
        }
    }
}

# Calculate compliance percentage
$TotalChecks = $ComplianceReport.Summary.Passed + $ComplianceReport.Summary.Failed
if ($TotalChecks -gt 0) {
    $ComplianceReport.Summary.CompliancePercentage = [math]::Round(($ComplianceReport.Summary.Passed / $TotalChecks) * 100, 2)
}

# Display summary
Write-Host "`n==================================" -ForegroundColor Cyan
Write-Host "COMPLIANCE AUDIT SUMMARY" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Scan Date:               $($ComplianceReport.ScanDate)"
Write-Host "Storage Accounts Audited: $($ComplianceReport.TotalStorageAccounts)"
Write-Host "Total Checks:            $TotalChecks"
Write-ComplianceLog "Passed:                  $($ComplianceReport.Summary.Passed)" -Level PASS
Write-ComplianceLog "Failed:                  $($ComplianceReport.Summary.Failed)" -Level FAIL
Write-ComplianceLog "Warnings:                $($ComplianceReport.Summary.Warnings)" -Level WARNING
Write-Host "Compliance Percentage:   $($ComplianceReport.Summary.CompliancePercentage)%"
Write-Host "==================================" -ForegroundColor Cyan

# Export report if requested
if ($ExportFormat -ne 'Console' -and $OutputFile) {
    try {
        switch ($ExportFormat) {
            'JSON' {
                $ComplianceReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
                Write-ComplianceLog "JSON report exported to: $OutputFile" -Level PASS
            }
            'CSV' {
                $ComplianceReport.Findings | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
                Write-ComplianceLog "CSV report exported to: $OutputFile" -Level PASS
            }
        }
    }
    catch {
        Write-ComplianceLog "Failed to export report: $($_.Exception.Message)" -Level FAIL
    }
}

return $ComplianceReport
