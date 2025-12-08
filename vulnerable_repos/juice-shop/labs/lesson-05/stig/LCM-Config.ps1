<#
.SYNOPSIS
    Configure Local Configuration Manager (LCM) for continuous STIG compliance.

.DESCRIPTION
    Sets up PowerShell DSC Local Configuration Manager to:
    - Monitor STIG compliance continuously (every 15 minutes)
    - Auto-correct configuration drift
    - Send compliance reports to centralized DSC pull server
    - Maintain audit evidence of compliance state

    This enables "continuous compliance" - configuration drift is detected
    and automatically remediated without manual intervention.

.PARAMETER PullServerURL
    URL of the DSC pull server (optional, uses push mode if not specified).

.PARAMETER RegistrationKey
    Registration key for DSC pull server authentication.

.PARAMETER Mode
    LCM mode: Push (default) or Pull.

.EXAMPLE
    .\LCM-Config.ps1 -Mode Push

.EXAMPLE
    .\LCM-Config.ps1 -Mode Pull -PullServerURL 'https://dsc.contoso.com/PSDscPullServer.svc' -RegistrationKey 'YOUR_KEY'

.NOTES
    Author: MS Press - GitHub Copilot for Cybersecurity Professionals
    Lesson: 05 - Continuous STIG Compliance
    Version: 1.0
    Requires: PowerShell 5.1+, Administrative privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Push', 'Pull')]
    [string]$Mode = 'Push',

    [Parameter(Mandatory = $false)]
    [string]$PullServerURL,

    [Parameter(Mandatory = $false)]
    [string]$RegistrationKey
)

# Check for administrative privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "This script requires administrative privileges. Please run as Administrator."
    exit 1
}

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "DSC LCM CONFIGURATION" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Mode: $Mode"
if ($Mode -eq 'Pull') {
    Write-Host "Pull Server: $PullServerURL"
}
Write-Host ""

# =======================
# LCM Configuration - Push Mode
# =======================

[DSCLocalConfigurationManager()]
Configuration LCMConfig_PushMode {
    Node localhost {
        Settings {
            # Refresh configuration every 15 minutes
            RefreshMode                    = 'Push'
            RefreshFrequencyMins           = 15
            ConfigurationModeFrequencyMins = 15

            # Automatically correct configuration drift
            ConfigurationMode              = 'ApplyAndAutoCorrect'

            # Reboot if needed to apply configuration
            RebootNodeIfNeeded             = $true

            # Allow module overwrites during updates
            AllowModuleOverwrite           = $true

            # Action after reboot
            ActionAfterReboot              = 'ContinueConfiguration'

            # Status retention (30 days of history)
            StatusRetentionTimeInDays      = 30
        }
    }
}

# =======================
# LCM Configuration - Pull Mode
# =======================

[DSCLocalConfigurationManager()]
Configuration LCMConfig_PullMode {
    param(
        [string]$PullServerURL,
        [string]$RegistrationKey
    )

    Node localhost {
        Settings {
            # Refresh configuration from pull server every 15 minutes
            RefreshMode                    = 'Pull'
            RefreshFrequencyMins           = 15
            ConfigurationModeFrequencyMins = 15

            # Automatically correct configuration drift
            ConfigurationMode              = 'ApplyAndAutoCorrect'

            # Reboot if needed to apply configuration
            RebootNodeIfNeeded             = $true

            # Allow module overwrites during updates
            AllowModuleOverwrite           = $true

            # Action after reboot
            ActionAfterReboot              = 'ContinueConfiguration'

            # Status retention (30 days of history)
            StatusRetentionTimeInDays      = 30

            # Certificate for secure communication (optional)
            CertificateID                  = $null
        }

        # Define pull server connection
        ConfigurationRepositoryWeb DSCPullServer {
            ServerURL          = $PullServerURL
            RegistrationKey    = $RegistrationKey
            ConfigurationNames = @('RemediateSTIG_WindowsServer2022')
            AllowUnsecureConnection = $false
        }

        # Reporting endpoint (send compliance status to pull server)
        ReportServerWeb DSCReportServer {
            ServerURL          = $PullServerURL
            RegistrationKey    = $RegistrationKey
            AllowUnsecureConnection = $false
        }

        # Resource repository (download DSC modules from pull server)
        ResourceRepositoryWeb DSCResourceServer {
            ServerURL          = $PullServerURL
            RegistrationKey    = $RegistrationKey
            AllowUnsecureConnection = $false
        }
    }
}

# =======================
# Generate and Apply LCM Configuration
# =======================

$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath 'LCMConfig'

try {
    Write-Host "Generating LCM configuration..." -ForegroundColor Yellow

    if ($Mode -eq 'Push') {
        LCMConfig_PushMode -OutputPath $OutputPath
    }
    else {
        if (-not $PullServerURL -or -not $RegistrationKey) {
            Write-Error "Pull mode requires -PullServerURL and -RegistrationKey parameters"
            exit 1
        }

        LCMConfig_PullMode -PullServerURL $PullServerURL -RegistrationKey $RegistrationKey -OutputPath $OutputPath
    }

    Write-Host "[OK] LCM configuration generated: $OutputPath" -ForegroundColor Green

    # Apply LCM configuration
    Write-Host "`nApplying LCM configuration..." -ForegroundColor Yellow
    Set-DscLocalConfigurationManager -Path $OutputPath -Force -Verbose

    Write-Host "[OK] LCM configuration applied successfully" -ForegroundColor Green

    # Verify LCM configuration
    Write-Host "`nVerifying LCM configuration..." -ForegroundColor Yellow
    $LCMConfig = Get-DscLocalConfigurationManager

    Write-Host "`n==================================" -ForegroundColor Cyan
    Write-Host "LCM CONFIGURATION SUMMARY" -ForegroundColor Cyan
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host "Refresh Mode:              $($LCMConfig.RefreshMode)"
    Write-Host "Configuration Mode:        $($LCMConfig.ConfigurationMode)"
    Write-Host "Refresh Frequency:         $($LCMConfig.RefreshFrequencyMins) minutes"
    Write-Host "Configuration Frequency:   $($LCMConfig.ConfigurationModeFrequencyMins) minutes"
    Write-Host "Reboot If Needed:          $($LCMConfig.RebootNodeIfNeeded)"
    Write-Host "Status Retention:          $($LCMConfig.StatusRetentionTimeInDays) days"
    Write-Host "==================================" -ForegroundColor Cyan

    if ($Mode -eq 'Pull') {
        Write-Host "`nPull Server Configuration:"
        foreach ($ConfigRepo in $LCMConfig.ConfigurationDownloadManagers) {
            Write-Host "  Server URL:    $($ConfigRepo.ServerURL)"
            Write-Host "  Configurations: $($ConfigRepo.ConfigurationNames -join ', ')"
        }
    }

    Write-Host "`n[INFO] LCM is now monitoring STIG compliance every 15 minutes" -ForegroundColor Cyan
    Write-Host "[INFO] Configuration drift will be automatically corrected" -ForegroundColor Cyan
    Write-Host "[INFO] View DSC status: Get-DscConfigurationStatus" -ForegroundColor Cyan
    Write-Host "[INFO] View LCM config: Get-DscLocalConfigurationManager" -ForegroundColor Cyan

}
catch {
    Write-Host "[ERROR] Failed to configure LCM: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# =======================
# Optional: Test LCM Operation
# =======================

Write-Host "`nWould you like to test LCM operation? (Y/N): " -ForegroundColor Yellow -NoNewline
$TestLCM = Read-Host

if ($TestLCM -eq 'Y' -or $TestLCM -eq 'y') {
    Write-Host "`nTesting LCM consistency check..." -ForegroundColor Yellow

    try {
        # Run consistency check (Test-DscConfiguration)
        $ConsistencyCheck = Test-DscConfiguration -Verbose

        if ($ConsistencyCheck) {
            Write-Host "[OK] Server is in desired state (STIG compliant)" -ForegroundColor Green
        }
        else {
            Write-Host "[WARNING] Server is NOT in desired state (configuration drift detected)" -ForegroundColor Yellow
            Write-Host "[INFO] LCM will automatically remediate during next consistency check" -ForegroundColor Cyan
        }

        # Show recent DSC operations
        Write-Host "`nRecent DSC Configuration Status:" -ForegroundColor Cyan
        Get-DscConfigurationStatus | Select-Object -First 5 | Format-Table -AutoSize
    }
    catch {
        Write-Host "[ERROR] LCM test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n[INFO] LCM configuration complete. Continuous STIG compliance is now active." -ForegroundColor Green
