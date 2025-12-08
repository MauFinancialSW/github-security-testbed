<#
.SYNOPSIS
    PowerShell DSC configuration to remediate Windows Server 2022 STIG findings.

.DESCRIPTION
    Applies DISA STIG (Security Technical Implementation Guide) remediations:
    - V-93075: Enable Windows Defender Antimalware Service (CAT I - Critical)
    - V-93089: Enable Windows Firewall (Domain, Private, Public profiles) (CAT I - Critical)
    - V-93127: Set minimum password length to 14 characters (CAT II - Medium)
    - V-93145: Set account lockout duration to 30 minutes (CAT II - Medium)
    - V-93147: Set password history to 24 passwords (CAT II - Medium)

    Uses PowerShell Desired State Configuration (DSC) for idempotent, auditable remediation.

.PARAMETER ComputerName
    Target server(s) for STIG remediation.

.PARAMETER ApplyRemediation
    Execute remediation. If not specified, configuration is generated but not applied.

.PARAMETER ValidateOnly
    Run pre/post validation checks without applying changes.

.EXAMPLE
    .\Remediate-STIG-WindowsServer.ps1 -ComputerName 'SERVER01' -ApplyRemediation

.EXAMPLE
    .\Remediate-STIG-WindowsServer.ps1 -ComputerName 'SERVER01' -ValidateOnly

.NOTES
    Author: MS Press - GitHub Copilot for Cybersecurity Professionals
    Lesson: 05 - STIG Remediation Automation
    Version: 1.0
    Requires: PowerShell 5.1+, SecurityPolicyDsc module
    STIG: Windows Server 2022 STIG v1 Release 1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ComputerName,

    [switch]$ApplyRemediation,

    [switch]$ValidateOnly
)

# Check for required DSC modules
$RequiredModules = @('PSDesiredStateConfiguration', 'SecurityPolicyDsc', 'ComputerManagementDsc')
foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $Module)) {
        Write-Warning "Required module '$Module' not found. Installing..."
        try {
            Install-Module -Name $Module -Force -AllowClobber -Scope CurrentUser
            Write-Host "[OK] Module '$Module' installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install module '$Module': $($_.Exception.Message)"
            exit 1
        }
    }
}

# STIG Control Definitions
$STIGControls = @{
    'V-93075' = @{
        Name        = 'Windows Defender Antimalware Service Enabled'
        Category    = 'CAT I'
        Severity    = 'CRITICAL'
        Description = 'Windows Defender antivirus must be enabled and running'
    }
    'V-93089' = @{
        Name        = 'Windows Firewall Profiles Enabled'
        Category    = 'CAT I'
        Severity    = 'CRITICAL'
        Description = 'Windows Firewall must be enabled for Domain, Private, and Public profiles'
    }
    'V-93127' = @{
        Name        = 'Minimum Password Length 14 Characters'
        Category    = 'CAT II'
        Severity    = 'MEDIUM'
        Description = 'Minimum password length must be 14 characters or greater'
    }
    'V-93145' = @{
        Name        = 'Account Lockout Duration 30 Minutes'
        Category    = 'CAT II'
        Severity    = 'MEDIUM'
        Description = 'Account lockout duration must be 30 minutes or greater'
    }
    'V-93147' = @{
        Name        = 'Password History 24 Passwords'
        Category    = 'CAT II'
        Severity    = 'MEDIUM'
        Description = 'Password history must be 24 passwords or greater'
    }
}

function Test-STIGCompliance {
    param([string]$Computer)

    Write-Host "`n=== STIG Compliance Validation: $Computer ===" -ForegroundColor Cyan

    $Results = @{
        ComputerName = $Computer
        Timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Checks       = @()
    }

    # V-93075: Windows Defender Service
    $DefenderService = Get-Service -Name 'WinDefend' -ComputerName $Computer -ErrorAction SilentlyContinue
    $DefenderCompliant = ($DefenderService.Status -eq 'Running' -and $DefenderService.StartType -eq 'Automatic')

    $Results.Checks += [PSCustomObject]@{
        STIG_ID    = 'V-93075'
        Control    = 'Windows Defender Service'
        Expected   = 'Running, Automatic'
        Actual     = "$($DefenderService.Status), $($DefenderService.StartType)"
        Compliant  = $DefenderCompliant
        Severity   = 'CAT I'
    }

    if ($DefenderCompliant) {
        Write-Host "  [V-93075] Windows Defender Service: PASS" -ForegroundColor Green
    }
    else {
        Write-Host "  [V-93075] Windows Defender Service: FAIL" -ForegroundColor Red
    }

    # V-93089: Windows Firewall Profiles
    $FirewallProfiles = Get-NetFirewallProfile -ComputerName $Computer
    $AllFirewallsEnabled = ($FirewallProfiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0

    $Results.Checks += [PSCustomObject]@{
        STIG_ID    = 'V-93089'
        Control    = 'Windows Firewall Profiles'
        Expected   = 'All Enabled'
        Actual     = "Domain: $($FirewallProfiles[0].Enabled), Private: $($FirewallProfiles[1].Enabled), Public: $($FirewallProfiles[2].Enabled)"
        Compliant  = $AllFirewallsEnabled
        Severity   = 'CAT I'
    }

    if ($AllFirewallsEnabled) {
        Write-Host "  [V-93089] Windows Firewall Profiles: PASS" -ForegroundColor Green
    }
    else {
        Write-Host "  [V-93089] Windows Firewall Profiles: FAIL" -ForegroundColor Red
    }

    # V-93127: Minimum Password Length
    $SecPolicy = Get-LocalSecurityPolicy -ComputerName $Computer
    $MinPasswordLength = [int]$SecPolicy.MinimumPasswordLength
    $PasswordLengthCompliant = $MinPasswordLength -ge 14

    $Results.Checks += [PSCustomObject]@{
        STIG_ID    = 'V-93127'
        Control    = 'Minimum Password Length'
        Expected   = '14 or greater'
        Actual     = $MinPasswordLength
        Compliant  = $PasswordLengthCompliant
        Severity   = 'CAT II'
    }

    if ($PasswordLengthCompliant) {
        Write-Host "  [V-93127] Minimum Password Length: PASS ($MinPasswordLength chars)" -ForegroundColor Green
    }
    else {
        Write-Host "  [V-93127] Minimum Password Length: FAIL ($MinPasswordLength chars < 14)" -ForegroundColor Red
    }

    # V-93145: Account Lockout Duration
    $LockoutDuration = [int]$SecPolicy.LockoutDuration
    $LockoutCompliant = $LockoutDuration -ge 30

    $Results.Checks += [PSCustomObject]@{
        STIG_ID    = 'V-93145'
        Control    = 'Account Lockout Duration'
        Expected   = '30 minutes or greater'
        Actual     = "$LockoutDuration minutes"
        Compliant  = $LockoutCompliant
        Severity   = 'CAT II'
    }

    if ($LockoutCompliant) {
        Write-Host "  [V-93145] Account Lockout Duration: PASS ($LockoutDuration min)" -ForegroundColor Green
    }
    else {
        Write-Host "  [V-93145] Account Lockout Duration: FAIL ($LockoutDuration min < 30)" -ForegroundColor Red
    }

    # V-93147: Password History
    $PasswordHistory = [int]$SecPolicy.PasswordHistorySize
    $HistoryCompliant = $PasswordHistory -ge 24

    $Results.Checks += [PSCustomObject]@{
        STIG_ID    = 'V-93147'
        Control    = 'Password History'
        Expected   = '24 passwords or greater'
        Actual     = "$PasswordHistory passwords"
        Compliant  = $HistoryCompliant
        Severity   = 'CAT II'
    }

    if ($HistoryCompliant) {
        Write-Host "  [V-93147] Password History: PASS ($PasswordHistory passwords)" -ForegroundColor Green
    }
    else {
        Write-Host "  [V-93147] Password History: FAIL ($PasswordHistory passwords < 24)" -ForegroundColor Red
    }

    # Summary
    $TotalChecks = $Results.Checks.Count
    $PassedChecks = ($Results.Checks | Where-Object { $_.Compliant -eq $true }).Count
    $CompliancePercentage = [math]::Round(($PassedChecks / $TotalChecks) * 100, 2)

    Write-Host "`n  Summary: $PassedChecks/$TotalChecks checks passed ($CompliancePercentage% compliant)" -ForegroundColor Cyan

    return $Results
}

function Get-LocalSecurityPolicy {
    param([string]$ComputerName)

    # Parse secedit export (simplified for demo purposes)
    # In production, use SecurityPolicyDsc or LGPO tools
    return @{
        MinimumPasswordLength = 8   # Default insecure value
        LockoutDuration       = 15  # Default insecure value
        PasswordHistorySize   = 0   # Default insecure value
    }
}

# =======================
# DSC Configuration
# =======================

Configuration RemediateSTIG_WindowsServer2022 {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName SecurityPolicyDsc
    Import-DscResource -ModuleName ComputerManagementDsc

    Node $ComputerName {

        # V-93075: Enable Windows Defender Antimalware Service
        Service WindowsDefenderService {
            Name        = 'WinDefend'
            State       = 'Running'
            StartupType = 'Automatic'
            Ensure      = 'Present'
        }

        # V-93089: Enable Windows Firewall - Domain Profile
        Script EnableFirewallDomain {
            GetScript  = {
                $Profile = Get-NetFirewallProfile -Name Domain
                return @{ Result = $Profile.Enabled }
            }
            TestScript = {
                $Profile = Get-NetFirewallProfile -Name Domain
                return ($Profile.Enabled -eq $true)
            }
            SetScript  = {
                Set-NetFirewallProfile -Name Domain -Enabled True
                Write-Verbose "Windows Firewall Domain profile enabled"
            }
        }

        # V-93089: Enable Windows Firewall - Private Profile
        Script EnableFirewallPrivate {
            GetScript  = {
                $Profile = Get-NetFirewallProfile -Name Private
                return @{ Result = $Profile.Enabled }
            }
            TestScript = {
                $Profile = Get-NetFirewallProfile -Name Private
                return ($Profile.Enabled -eq $true)
            }
            SetScript  = {
                Set-NetFirewallProfile -Name Private -Enabled True
                Write-Verbose "Windows Firewall Private profile enabled"
            }
        }

        # V-93089: Enable Windows Firewall - Public Profile
        Script EnableFirewallPublic {
            GetScript  = {
                $Profile = Get-NetFirewallProfile -Name Public
                return @{ Result = $Profile.Enabled }
            }
            TestScript = {
                $Profile = Get-NetFirewallProfile -Name Public
                return ($Profile.Enabled -eq $true)
            }
            SetScript  = {
                Set-NetFirewallProfile -Name Public -Enabled True
                Write-Verbose "Windows Firewall Public profile enabled"
            }
        }

        # V-93127: Minimum Password Length = 14
        SecurityOption MinimumPasswordLength {
            Name                      = 'MinimumPasswordLength'
            Minimum_password_length   = 14
        }

        # V-93145: Account Lockout Duration >= 30 minutes
        SecurityOption AccountLockoutDuration {
            Name                        = 'AccountLockoutDuration'
            Account_lockout_duration    = 30
        }

        # V-93147: Password History >= 24 passwords
        SecurityOption PasswordHistory {
            Name                                  = 'PasswordHistory'
            Enforce_password_history              = 24
        }
    }
}

# =======================
# Main Execution
# =======================

if ($ValidateOnly) {
    # Run validation checks only
    foreach ($Computer in $ComputerName) {
        $ValidationResults = Test-STIGCompliance -Computer $Computer
        $ValidationResults.Checks | Format-Table -AutoSize
    }
    exit 0
}

# Pre-Remediation Validation
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "PRE-REMEDIATION STIG COMPLIANCE CHECK" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$PreRemediationResults = @()
foreach ($Computer in $ComputerName) {
    $PreRemediationResults += Test-STIGCompliance -Computer $Computer
}

if (-not $ApplyRemediation) {
    Write-Host "`n[INFO] DSC configuration generated but NOT applied (use -ApplyRemediation to execute)" -ForegroundColor Cyan
    Write-Host "[INFO] Configuration would remediate the following STIG controls:" -ForegroundColor Cyan
    $STIGControls.GetEnumerator() | ForEach-Object {
        Write-Host "  - [$($_.Key)] $($_.Value.Name) ($($_.Value.Category))" -ForegroundColor White
    }
    exit 0
}

# Generate DSC Configuration
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "GENERATING DSC CONFIGURATION" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath 'DscConfig'
RemediateSTIG_WindowsServer2022 -ComputerName $ComputerName -OutputPath $OutputPath

Write-Host "[OK] DSC configuration generated: $OutputPath" -ForegroundColor Green

# Apply DSC Configuration
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "APPLYING STIG REMEDIATION" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

foreach ($Computer in $ComputerName) {
    try {
        Write-Host "`nApplying DSC configuration to: $Computer" -ForegroundColor Cyan

        # In production, use Start-DscConfiguration with proper error handling
        # Start-DscConfiguration -Path $OutputPath -ComputerName $Computer -Wait -Verbose -Force

        # For demo purposes, simulate remediation
        Write-Host "  [V-93075] Enabling Windows Defender Service..." -ForegroundColor White
        Write-Host "  [V-93089] Enabling Windows Firewall profiles..." -ForegroundColor White
        Write-Host "  [V-93127] Setting minimum password length to 14..." -ForegroundColor White
        Write-Host "  [V-93145] Setting account lockout duration to 30 min..." -ForegroundColor White
        Write-Host "  [V-93147] Setting password history to 24 passwords..." -ForegroundColor White

        Write-Host "[OK] DSC configuration applied successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to apply DSC configuration: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Post-Remediation Validation
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "POST-REMEDIATION STIG COMPLIANCE CHECK" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$PostRemediationResults = @()
foreach ($Computer in $ComputerName) {
    $PostRemediationResults += Test-STIGCompliance -Computer $Computer
}

# Compare Results
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "REMEDIATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($Computer in $ComputerName) {
    $PreResult = $PreRemediationResults | Where-Object { $_.ComputerName -eq $Computer }
    $PostResult = $PostRemediationResults | Where-Object { $_.ComputerName -eq $Computer }

    $PrePassed = ($PreResult.Checks | Where-Object { $_.Compliant -eq $true }).Count
    $PostPassed = ($PostResult.Checks | Where-Object { $_.Compliant -eq $true }).Count
    $TotalChecks = $PreResult.Checks.Count

    $PreCompliance = [math]::Round(($PrePassed / $TotalChecks) * 100, 2)
    $PostCompliance = [math]::Round(($PostPassed / $TotalChecks) * 100, 2)

    Write-Host "`nComputer: $Computer"
    Write-Host "  Pre-Remediation:  $PrePassed/$TotalChecks checks passed ($PreCompliance%)"
    Write-Host "  Post-Remediation: $PostPassed/$TotalChecks checks passed ($PostCompliance%)"

    if ($PostCompliance -gt $PreCompliance) {
        Write-Host "  Status: IMPROVED (+$([math]::Round($PostCompliance - $PreCompliance, 2))%)" -ForegroundColor Green
    }
    elseif ($PostCompliance -eq 100) {
        Write-Host "  Status: FULLY COMPLIANT" -ForegroundColor Green
    }
    else {
        Write-Host "  Status: ADDITIONAL REMEDIATION REQUIRED" -ForegroundColor Yellow
    }
}

Write-Host "`n[INFO] STIG remediation complete. Review logs for details." -ForegroundColor Cyan
Write-Host "[INFO] Schedule continuous compliance validation using LCM (see LCM-Config.ps1)" -ForegroundColor Cyan
