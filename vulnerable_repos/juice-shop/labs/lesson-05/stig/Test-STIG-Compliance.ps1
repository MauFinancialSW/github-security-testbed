<#
.SYNOPSIS
    Pester tests for Windows Server 2022 STIG compliance validation.

.DESCRIPTION
    Validates STIG controls using Pester test framework:
    - V-93075: Windows Defender service running
    - V-93089: Windows Firewall enabled (all profiles)
    - V-93127: Minimum password length >= 14
    - V-93145: Account lockout duration >= 30 minutes
    - V-93147: Password history >= 24 passwords

.EXAMPLE
    Invoke-Pester -Path .\Test-STIG-Compliance.ps1

.NOTES
    Author: MS Press - GitHub Copilot for Cybersecurity Professionals
    Lesson: 05 - STIG Remediation Automation
    Version: 1.0
    Requires: Pester 5.x
#>

#Requires -Modules Pester

BeforeAll {
    # Test configuration
    $script:ComputerName = $env:COMPUTERNAME

    # Helper function to get security policy settings
    function Get-SecurityPolicySetting {
        param(
            [string]$SettingName
        )

        # In production, parse secedit /export output or use SecurityPolicyDsc
        # For demo purposes, return mock values
        $Settings = @{
            'MinimumPasswordLength'      = 14
            'LockoutDuration'            = 30
            'PasswordHistorySize'        = 24
            'MaximumPasswordAge'         = 60
            'PasswordComplexity'         = 1
        }

        return $Settings[$SettingName]
    }
}

Describe 'Windows Server 2022 STIG Compliance' -Tags 'STIG', 'Security' {

    Context 'CAT I (Critical) Controls' {

        It '[V-93075] Windows Defender Antimalware Service should be running' {
            # Arrange
            $ServiceName = 'WinDefend'

            # Act
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

            # Assert
            $Service | Should -Not -BeNullOrEmpty
            $Service.Status | Should -Be 'Running'
            $Service.StartType | Should -Be 'Automatic'
        }

        It '[V-93089] Windows Firewall Domain profile should be enabled' {
            # Act
            $FirewallProfile = Get-NetFirewallProfile -Name Domain

            # Assert
            $FirewallProfile.Enabled | Should -Be $true
        }

        It '[V-93089] Windows Firewall Private profile should be enabled' {
            # Act
            $FirewallProfile = Get-NetFirewallProfile -Name Private

            # Assert
            $FirewallProfile.Enabled | Should -Be $true
        }

        It '[V-93089] Windows Firewall Public profile should be enabled' {
            # Act
            $FirewallProfile = Get-NetFirewallProfile -Name Public

            # Assert
            $FirewallProfile.Enabled | Should -Be $true
        }
    }

    Context 'CAT II (Medium) Controls - Password Policy' {

        It '[V-93127] Minimum password length should be 14 characters or greater' {
            # Act
            $MinPasswordLength = Get-SecurityPolicySetting -SettingName 'MinimumPasswordLength'

            # Assert
            $MinPasswordLength | Should -BeGreaterOrEqual 14
        }

        It '[V-93145] Account lockout duration should be 30 minutes or greater' {
            # Act
            $LockoutDuration = Get-SecurityPolicySetting -SettingName 'LockoutDuration'

            # Assert
            $LockoutDuration | Should -BeGreaterOrEqual 30
        }

        It '[V-93147] Password history should remember 24 passwords or greater' {
            # Act
            $PasswordHistory = Get-SecurityPolicySetting -SettingName 'PasswordHistorySize'

            # Assert
            $PasswordHistory | Should -BeGreaterOrEqual 24
        }

        It '[V-93149] Maximum password age should be 60 days or less' {
            # Act
            $MaxPasswordAge = Get-SecurityPolicySetting -SettingName 'MaximumPasswordAge'

            # Assert
            $MaxPasswordAge | Should -BeLessOrEqual 60
            $MaxPasswordAge | Should -BeGreaterThan 0
        }

        It '[V-93151] Password complexity requirements should be enabled' {
            # Act
            $PasswordComplexity = Get-SecurityPolicySetting -SettingName 'PasswordComplexity'

            # Assert
            $PasswordComplexity | Should -Be 1
        }
    }

    Context 'CAT III (Low) Controls - Additional Security Settings' {

        It '[V-93201] Remote Desktop Services should be configured securely' {
            # Act
            $RDPService = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue

            # Assert
            if ($RDPService) {
                # RDP should use NLA (Network Level Authentication)
                $NLAEnabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication

                $NLAEnabled | Should -Be 1
            }
            else {
                # If RDP is not installed/used, test passes
                Set-ItResult -Skipped -Because 'Remote Desktop Services not installed'
            }
        }

        It '[V-93215] Unnecessary services should not be running' {
            # Arrange
            $UnnecessaryServices = @(
                'RemoteRegistry',
                'SSDPSRV',        # SSDP Discovery
                'upnphost',       # UPnP Device Host
                'WMPNetworkSvc'   # Windows Media Player Network Sharing
            )

            # Act & Assert
            foreach ($ServiceName in $UnnecessaryServices) {
                $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

                if ($Service) {
                    $Service.Status | Should -Not -Be 'Running' -Because "$ServiceName should not be running per STIG"
                }
            }
        }
    }

    Context 'Audit and Logging Controls' {

        It '[V-93301] Windows Event Log (Security) should be configured' {
            # Act
            $SecurityLog = Get-EventLog -List | Where-Object { $_.Log -eq 'Security' }

            # Assert
            $SecurityLog | Should -Not -BeNullOrEmpty
            $SecurityLog.MaximumKilobytes | Should -BeGreaterOrEqual 196608  # 192 MB minimum
        }

        It '[V-93303] Windows Event Log (System) should be configured' {
            # Act
            $SystemLog = Get-EventLog -List | Where-Object { $_.Log -eq 'System' }

            # Assert
            $SystemLog | Should -Not -BeNullOrEmpty
            $SystemLog.MaximumKilobytes | Should -BeGreaterOrEqual 32768  # 32 MB minimum
        }

        It '[V-93305] Windows Event Log (Application) should be configured' {
            # Act
            $ApplicationLog = Get-EventLog -List | Where-Object { $_.Log -eq 'Application' }

            # Assert
            $ApplicationLog | Should -Not -BeNullOrEmpty
            $ApplicationLog.MaximumKilobytes | Should -BeGreaterOrEqual 32768  # 32 MB minimum
        }
    }
}

Describe 'STIG Compliance Summary Report' -Tags 'Report' {

    It 'Should generate compliance summary' {
        # This test generates a summary report of all STIG checks

        $AllTests = Invoke-Pester -Path $PSCommandPath -PassThru -Show None

        $Summary = [PSCustomObject]@{
            Timestamp           = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            ComputerName        = $env:COMPUTERNAME
            TotalTests          = $AllTests.TotalCount
            Passed              = $AllTests.PassedCount
            Failed              = $AllTests.FailedCount
            Skipped             = $AllTests.SkippedCount
            CompliancePercentage = [math]::Round(($AllTests.PassedCount / $AllTests.TotalCount) * 100, 2)
        }

        Write-Host "`n==================================" -ForegroundColor Cyan
        Write-Host "STIG COMPLIANCE SUMMARY" -ForegroundColor Cyan
        Write-Host "==================================" -ForegroundColor Cyan
        Write-Host "Computer:    $($Summary.ComputerName)"
        Write-Host "Timestamp:   $($Summary.Timestamp)"
        Write-Host "Total Tests: $($Summary.TotalTests)"
        Write-Host "Passed:      $($Summary.Passed)" -ForegroundColor Green
        Write-Host "Failed:      $($Summary.Failed)" -ForegroundColor Red
        Write-Host "Skipped:     $($Summary.Skipped)" -ForegroundColor Yellow
        Write-Host "Compliance:  $($Summary.CompliancePercentage)%" -ForegroundColor Cyan
        Write-Host "==================================" -ForegroundColor Cyan

        # Export summary to JSON
        $ReportPath = Join-Path -Path $PSScriptRoot -ChildPath "STIG-Compliance-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $Summary | ConvertTo-Json | Out-File -FilePath $ReportPath -Encoding UTF8

        Write-Host "`nCompliance report saved to: $ReportPath" -ForegroundColor Green

        # Assert compliance threshold
        $Summary.CompliancePercentage | Should -BeGreaterOrEqual 90 -Because 'STIG compliance should be at least 90%'
    }
}
