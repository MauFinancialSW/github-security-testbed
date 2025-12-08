<#
.SYNOPSIS
    CIS Microsoft Azure Foundations Benchmark compliance audit for Azure SQL Database.

.DESCRIPTION
    Validates Azure SQL Database resources against CIS benchmark controls:
    - CIS 4.8: Transparent Data Encryption (TDE) enabled
    - CIS 4.9: Azure Active Directory authentication configured
    - CIS 4.11: Firewall rules do not allow 0.0.0.0/0 (ALLOW ALL)
    - CIS 4.12: Audit logging enabled

    Returns PASS/FAIL/WARNING for each control with specific remediation commands.

.PARAMETER SubscriptionId
    Azure subscription ID to audit.

.PARAMETER ExportFormat
    Output format: JSON, CSV, or Console (default).

.PARAMETER OutputFile
    Path to export compliance report.

.EXAMPLE
    .\Audit-CIS-AzureSQL.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -Verbose

.EXAMPLE
    .\Audit-CIS-AzureSQL.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ExportFormat JSON -OutputFile "compliance-report.json"

.NOTES
    Author: MS Press - GitHub Copilot for Cybersecurity Professionals
    Lesson: 05 - Compliance Automation
    Version: 1.0
    Requires: Az.Sql PowerShell module
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

#Requires -Modules Az.Sql, Az.Accounts

# CIS Benchmark Control Definitions
$CISControls = @{
    'CIS-4.8' = @{
        Name        = 'Transparent Data Encryption (TDE) Enabled'
        Description = 'Ensures Azure SQL databases are encrypted at rest'
        Severity    = 'HIGH'
    }
    'CIS-4.9' = @{
        Name        = 'Azure AD Authentication Configured'
        Description = 'Ensures Azure Active Directory authentication is enabled'
        Severity    = 'HIGH'
    }
    'CIS-4.11' = @{
        Name        = 'Firewall Rule 0.0.0.0/0 Not Allowed'
        Description = 'Ensures firewall does not allow unrestricted access'
        Severity    = 'CRITICAL'
    }
    'CIS-4.12' = @{
        Name        = 'Audit Logging Enabled'
        Description = 'Ensures database audit logging is configured'
        Severity    = 'MEDIUM'
    }
}

# Compliance report structure
$ComplianceReport = [PSCustomObject]@{
    ScanDate              = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    SubscriptionId        = $SubscriptionId
    TotalServers          = 0
    TotalDatabases        = 0
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

# Get all SQL Servers in subscription
Write-ComplianceLog "Retrieving Azure SQL Servers..." -Level INFO
$SqlServers = Get-AzSqlServer
$ComplianceReport.TotalServers = $SqlServers.Count

if ($SqlServers.Count -eq 0) {
    Write-ComplianceLog "No Azure SQL Servers found in subscription" -Level WARNING
    exit 0
}

Write-ComplianceLog "Found $($SqlServers.Count) SQL Server(s)" -Level INFO

# Audit each SQL Server
foreach ($Server in $SqlServers) {
    Write-ComplianceLog "`nAuditing SQL Server: $($Server.ServerName)" -Level INFO

    # Get all databases on this server
    $Databases = Get-AzSqlDatabase -ServerName $Server.ServerName -ResourceGroupName $Server.ResourceGroupName |
                 Where-Object { $_.DatabaseName -ne 'master' }

    $ComplianceReport.TotalDatabases += $Databases.Count

    foreach ($Database in $Databases) {
        Write-ComplianceLog "  Checking database: $($Database.DatabaseName)" -Level INFO

        # =======================
        # CIS 4.8: TDE Enabled
        # =======================
        try {
            $TDE = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $Server.ServerName `
                                                               -ResourceGroupName $Server.ResourceGroupName `
                                                               -DatabaseName $Database.DatabaseName

            if ($TDE.State -eq 'Enabled') {
                Write-ComplianceLog "    [CIS-4.8] TDE Enabled: PASS" -Level PASS
                $ComplianceReport.Summary.Passed++
            }
            else {
                Write-ComplianceLog "    [CIS-4.8] TDE Disabled: FAIL" -Level FAIL
                $ComplianceReport.Summary.Failed++

                $ComplianceReport.Findings += [PSCustomObject]@{
                    ControlId    = 'CIS-4.8'
                    ControlName  = $CISControls['CIS-4.8'].Name
                    Status       = 'FAIL'
                    Severity     = $CISControls['CIS-4.8'].Severity
                    ResourceType = 'SQL Database'
                    ResourceName = "$($Server.ServerName)/$($Database.DatabaseName)"
                    Finding      = 'Transparent Data Encryption is not enabled'
                    Remediation  = "Set-AzSqlDatabaseTransparentDataEncryption -ServerName '$($Server.ServerName)' -ResourceGroupName '$($Server.ResourceGroupName)' -DatabaseName '$($Database.DatabaseName)' -State 'Enabled'"
                }
            }
        }
        catch {
            Write-ComplianceLog "    [CIS-4.8] TDE Check Error: $($_.Exception.Message)" -Level WARNING
            $ComplianceReport.Summary.Warnings++
        }

        # =======================
        # CIS 4.12: Audit Logging
        # =======================
        try {
            $AuditPolicy = Get-AzSqlDatabaseAudit -ServerName $Server.ServerName `
                                                   -ResourceGroupName $Server.ResourceGroupName `
                                                   -DatabaseName $Database.DatabaseName

            if ($AuditPolicy.BlobStorageTargetState -eq 'Enabled' -or $AuditPolicy.EventHubTargetState -eq 'Enabled' -or $AuditPolicy.LogAnalyticsTargetState -eq 'Enabled') {
                Write-ComplianceLog "    [CIS-4.12] Audit Logging Enabled: PASS" -Level PASS
                $ComplianceReport.Summary.Passed++
            }
            else {
                Write-ComplianceLog "    [CIS-4.12] Audit Logging Disabled: FAIL" -Level FAIL
                $ComplianceReport.Summary.Failed++

                $ComplianceReport.Findings += [PSCustomObject]@{
                    ControlId    = 'CIS-4.12'
                    ControlName  = $CISControls['CIS-4.12'].Name
                    Status       = 'FAIL'
                    Severity     = $CISControls['CIS-4.12'].Severity
                    ResourceType = 'SQL Database'
                    ResourceName = "$($Server.ServerName)/$($Database.DatabaseName)"
                    Finding      = 'Database audit logging is not configured'
                    Remediation  = "Set-AzSqlDatabaseAudit -ServerName '$($Server.ServerName)' -ResourceGroupName '$($Server.ResourceGroupName)' -DatabaseName '$($Database.DatabaseName)' -BlobStorageTargetState Enabled -StorageAccountResourceId '/subscriptions/$SubscriptionId/resourceGroups/YOUR_RG/providers/Microsoft.Storage/storageAccounts/YOUR_STORAGE'"
                }
            }
        }
        catch {
            Write-ComplianceLog "    [CIS-4.12] Audit Logging Check Error: $($_.Exception.Message)" -Level WARNING
            $ComplianceReport.Summary.Warnings++
        }
    }

    # =======================
    # CIS 4.9: Azure AD Authentication
    # =======================
    try {
        $AADAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $Server.ServerName `
                                                                 -ResourceGroupName $Server.ResourceGroupName `
                                                                 -ErrorAction SilentlyContinue

        if ($AADAdmin) {
            Write-ComplianceLog "  [CIS-4.9] Azure AD Authentication Configured: PASS" -Level PASS
            $ComplianceReport.Summary.Passed++
        }
        else {
            Write-ComplianceLog "  [CIS-4.9] Azure AD Authentication Not Configured: FAIL" -Level FAIL
            $ComplianceReport.Summary.Failed++

            $ComplianceReport.Findings += [PSCustomObject]@{
                ControlId    = 'CIS-4.9'
                ControlName  = $CISControls['CIS-4.9'].Name
                Status       = 'FAIL'
                Severity     = $CISControls['CIS-4.9'].Severity
                ResourceType = 'SQL Server'
                ResourceName = $Server.ServerName
                Finding      = 'Azure Active Directory authentication is not configured'
                Remediation  = "Set-AzSqlServerActiveDirectoryAdministrator -ServerName '$($Server.ServerName)' -ResourceGroupName '$($Server.ResourceGroupName)' -DisplayName 'DBA Group' -ObjectId 'YOUR_AAD_GROUP_OBJECT_ID'"
            }
        }
    }
    catch {
        Write-ComplianceLog "  [CIS-4.9] Azure AD Authentication Check Error: $($_.Exception.Message)" -Level WARNING
        $ComplianceReport.Summary.Warnings++
    }

    # =======================
    # CIS 4.11: Firewall Rules (No 0.0.0.0/0)
    # =======================
    try {
        $FirewallRules = Get-AzSqlServerFirewallRule -ServerName $Server.ServerName `
                                                      -ResourceGroupName $Server.ResourceGroupName

        $DangerousRules = $FirewallRules | Where-Object {
            $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '255.255.255.255'
        }

        if ($DangerousRules.Count -eq 0) {
            Write-ComplianceLog "  [CIS-4.11] No Unrestricted Firewall Rules: PASS" -Level PASS
            $ComplianceReport.Summary.Passed++
        }
        else {
            Write-ComplianceLog "  [CIS-4.11] Unrestricted Firewall Rule Found: FAIL" -Level FAIL
            $ComplianceReport.Summary.Failed++

            foreach ($Rule in $DangerousRules) {
                $ComplianceReport.Findings += [PSCustomObject]@{
                    ControlId    = 'CIS-4.11'
                    ControlName  = $CISControls['CIS-4.11'].Name
                    Status       = 'FAIL'
                    Severity     = $CISControls['CIS-4.11'].Severity
                    ResourceType = 'SQL Server Firewall Rule'
                    ResourceName = "$($Server.ServerName)/$($Rule.FirewallRuleName)"
                    Finding      = "Firewall rule allows unrestricted access (0.0.0.0/0)"
                    Remediation  = "Remove-AzSqlServerFirewallRule -ServerName '$($Server.ServerName)' -ResourceGroupName '$($Server.ResourceGroupName)' -FirewallRuleName '$($Rule.FirewallRuleName)'"
                }
            }
        }
    }
    catch {
        Write-ComplianceLog "  [CIS-4.11] Firewall Rules Check Error: $($_.Exception.Message)" -Level WARNING
        $ComplianceReport.Summary.Warnings++
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
Write-Host "SQL Servers Audited:     $($ComplianceReport.TotalServers)"
Write-Host "Databases Audited:       $($ComplianceReport.TotalDatabases)"
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

# Return compliance report object
return $ComplianceReport
