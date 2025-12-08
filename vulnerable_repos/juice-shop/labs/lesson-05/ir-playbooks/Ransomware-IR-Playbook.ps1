<#
.SYNOPSIS
    Automated incident response playbook for ransomware detection and containment.

.DESCRIPTION
    Multi-phase incident response automation for ransomware attacks:

    Phase 1: DETECTION & VALIDATION (automated)
    - Query Azure Log Analytics for suspicious account creation
    - Identify file encryption patterns
    - Cross-reference with threat intelligence
    - Alert SOC team with initial findings

    Phase 2: CONTAINMENT (semi-automated, requires approval)
    - Isolate affected VMs (network disconnection)
    - Terminate suspicious processes
    - Revoke active sessions for compromised accounts
    - Block attacker IP addresses at firewall

    Phase 3: ERADICATION (automated)
    - Remove suspicious user accounts
    - Delete persistence mechanisms (scheduled tasks, registry keys)
    - Remove malware files (after forensic preservation)

    Phase 5: EVIDENCE COLLECTION (automated)
    - Export Windows Event Logs
    - Calculate file hashes for malware samples
    - Archive all evidence with cryptographic integrity

.PARAMETER VirtualMachineName
    Target Azure VM for incident response.

.PARAMETER ResourceGroupName
    Resource group containing the VM.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER IncidentId
    Incident tracking ID (e.g., Azure Sentinel incident number).

.PARAMETER ExecuteContainment
    Execute containment actions (requires manual approval).

.PARAMETER SkipApproval
    Skip approval prompt for containment (use with caution).

.EXAMPLE
    .\Ransomware-IR-Playbook.ps1 -VirtualMachineName 'vm-prod-01' -ResourceGroupName 'prod-rg' -SubscriptionId 'YOUR_SUB_ID' -IncidentId 'INC-12345'

.EXAMPLE
    .\Ransomware-IR-Playbook.ps1 -VirtualMachineName 'vm-prod-01' -ResourceGroupName 'prod-rg' -SubscriptionId 'YOUR_SUB_ID' -ExecuteContainment

.NOTES
    Author: MS Press - GitHub Copilot for Cybersecurity Professionals
    Lesson: 05 - Incident Response Automation
    Version: 1.0
    Requires: Az.Compute, Az.Network, Az.OperationalInsights modules
    Triggered by: Azure Sentinel alert or manual invocation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VirtualMachineName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$IncidentId = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [Parameter(Mandatory = $false)]
    [switch]$ExecuteContainment,

    [Parameter(Mandatory = $false)]
    [switch]$SkipApproval
)

#Requires -Modules Az.Compute, Az.Network, Az.OperationalInsights

# Incident response configuration
$IRConfig = @{
    LogAnalyticsWorkspaceId = $null  # Set this to your Log Analytics workspace ID
    EvidencePath            = "C:\IREvidence\$IncidentId"
    SuspiciousUsernames     = @('hacker', 'admin', 'test', 'backdoor')
    MalwareExtensions       = @('.locked', '.encryptor', '.crypto', '.encrypted', '.wannacry', '.ryuk')
    SOCEmail                = 'soc@contoso.com'
}

# Incident tracking
$IncidentReport = @{
    IncidentId       = $IncidentId
    StartTime        = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    VirtualMachine   = $VirtualMachineName
    ResourceGroup    = $ResourceGroupName
    Subscription     = $SubscriptionId
    DetectionPhase   = @{}
    ContainmentPhase = @{}
    EradicationPhase = @{}
    EvidencePhase    = @{}
    Status           = 'In Progress'
}

function Write-IRLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL')]
        [string]$Level = 'INFO'
    )

    $Color = switch ($Level) {
        'SUCCESS'  { 'Green' }
        'WARNING'  { 'Yellow' }
        'ERROR'    { 'Red' }
        'CRITICAL' { 'Magenta' }
        default    { 'White' }
    }

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "[$Timestamp] [$Level] $Message"

    Write-Host $LogEntry -ForegroundColor $Color

    # Log to file for audit evidence
    $LogFile = Join-Path -Path $PSScriptRoot -ChildPath "IR-Playbook-$IncidentId.log"
    Add-Content -Path $LogFile -Value $LogEntry
}

# =======================
# PHASE 1: DETECTION & VALIDATION
# =======================

Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "PHASE 1: DETECTION & VALIDATION" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

Write-IRLog "Starting incident response for VM: $VirtualMachineName" -Level INFO
Write-IRLog "Incident ID: $IncidentId" -Level INFO

# Connect to Azure
try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    Write-IRLog "Connected to Azure subscription: $SubscriptionId" -Level SUCCESS
}
catch {
    Write-IRLog "Failed to connect to Azure: $($_.Exception.Message)" -Level ERROR
    exit 1
}

# Query Log Analytics for suspicious account creation events
Write-IRLog "Querying Azure Log Analytics for suspicious account creation..." -Level INFO

# KQL Query for suspicious account creation
$KQL_AccountCreation = @'
SecurityEvent
| where EventID == 4720  // Account created
| where TimeGenerated > ago(24h)
| where Account contains "hacker" or Account contains "admin" or Account contains "test"
| project TimeGenerated, Computer, Account, SubjectUserName, NewAccountName
| order by TimeGenerated desc
'@

Write-Host "`nKQL Query (Account Creation):" -ForegroundColor Cyan
Write-Host $KQL_AccountCreation -ForegroundColor Gray

# Simulated query results for demo
$SuspiciousAccountEvents = @(
    [PSCustomObject]@{
        TimeGenerated   = (Get-Date).AddHours(-2)
        Computer        = $VirtualMachineName
        Account         = 'hacker'
        SubjectUserName = 'SYSTEM'
        NewAccountName  = 'hacker'
    }
)

if ($SuspiciousAccountEvents.Count -gt 0) {
    Write-IRLog "ALERT: Found $($SuspiciousAccountEvents.Count) suspicious account creation event(s)" -Level CRITICAL
    $IncidentReport.DetectionPhase.SuspiciousAccounts = $SuspiciousAccountEvents
}
else {
    Write-IRLog "No suspicious account creation events detected" -Level INFO
}

# Query for file encryption patterns
Write-IRLog "Querying for file encryption patterns..." -Level INFO

$KQL_FileEncryption = @'
SecurityEvent
| where EventID in (4663, 4656)  // File access events
| where ObjectName endswith ".locked" or ObjectName endswith ".encryptor" or ObjectName endswith ".crypto"
| where TimeGenerated > ago(24h)
| summarize EncryptedFileCount = count() by Computer, ProcessName
| where EncryptedFileCount > 10
| order by EncryptedFileCount desc
'@

Write-Host "`nKQL Query (File Encryption):" -ForegroundColor Cyan
Write-Host $KQL_FileEncryption -ForegroundColor Gray

# Simulated encryption activity detection
$EncryptionActivity = @(
    [PSCustomObject]@{
        Computer           = $VirtualMachineName
        ProcessName        = 'update.exe'
        EncryptedFileCount = 437
    }
)

if ($EncryptionActivity.Count -gt 0) {
    Write-IRLog "ALERT: Detected file encryption activity ($($EncryptionActivity[0].EncryptedFileCount) files)" -Level CRITICAL
    $IncidentReport.DetectionPhase.EncryptionActivity = $EncryptionActivity
}

# Query for suspicious PowerShell execution
$KQL_PowerShell = @'
SecurityEvent
| where EventID == 4688  // Process creation
| where Process contains "powershell.exe"
| where CommandLine contains "-NoProfile" or CommandLine contains "-ExecutionPolicy Bypass"
| where TimeGenerated > ago(24h)
| project TimeGenerated, Computer, CommandLine, ParentProcessName
| order by TimeGenerated desc
'@

Write-Host "`nKQL Query (Suspicious PowerShell):" -ForegroundColor Cyan
Write-Host $KQL_PowerShell -ForegroundColor Gray

# Simulated suspicious PowerShell detection
$SuspiciousPowerShell = @(
    [PSCustomObject]@{
        TimeGenerated     = (Get-Date).AddHours(-2)
        Computer          = $VirtualMachineName
        CommandLine       = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "net user hacker P@ssw0rd123 /add"'
        ParentProcessName = 'update.exe'
    }
)

if ($SuspiciousPowerShell.Count -gt 0) {
    Write-IRLog "ALERT: Detected suspicious PowerShell execution" -Level CRITICAL
    Write-IRLog "Command: $($SuspiciousPowerShell[0].CommandLine)" -Level WARNING
    $IncidentReport.DetectionPhase.SuspiciousPowerShell = $SuspiciousPowerShell
}

# Detection summary
Write-Host "`n--- DETECTION SUMMARY ---" -ForegroundColor Cyan
Write-Host "Suspicious Accounts:     $($SuspiciousAccountEvents.Count)"
Write-Host "Encryption Activity:     $($EncryptionActivity[0].EncryptedFileCount) files"
Write-Host "Suspicious Commands:     $($SuspiciousPowerShell.Count)"
Write-Host "Severity:                CRITICAL - Ransomware indicators detected" -ForegroundColor Red

# =======================
# PHASE 2: CONTAINMENT
# =======================

if (-not $ExecuteContainment) {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "PHASE 2: CONTAINMENT (REQUIRES APPROVAL)" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow

    Write-IRLog "Containment phase requires approval. Use -ExecuteContainment to proceed." -Level WARNING
    Write-IRLog "Recommended actions:" -Level INFO
    Write-IRLog "  1. Isolate VM network interface" -Level INFO
    Write-IRLog "  2. Terminate suspicious processes (update.exe)" -Level INFO
    Write-IRLog "  3. Revoke active sessions for 'hacker' account" -Level INFO
    Write-IRLog "  4. Block attacker IP addresses" -Level INFO

    Write-Host "`n[ACTION REQUIRED] Review detection findings and execute with -ExecuteContainment" -ForegroundColor Yellow
    exit 0
}

Write-Host "`n========================================" -ForegroundColor Red
Write-Host "PHASE 2: CONTAINMENT (EXECUTING)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

if (-not $SkipApproval) {
    Write-Host "`nWARNING: Containment will isolate VM and disrupt services." -ForegroundColor Yellow
    Write-Host "VM: $VirtualMachineName" -ForegroundColor Yellow
    Write-Host "`nProceed with containment? (Y/N): " -ForegroundColor Red -NoNewline
    $Approval = Read-Host

    if ($Approval -ne 'Y' -and $Approval -ne 'y') {
        Write-IRLog "Containment cancelled by operator" -Level WARNING
        exit 0
    }
}

Write-IRLog "Containment approved - executing..." -Level CRITICAL

# Get VM object
try {
    $VM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VirtualMachineName -ErrorAction Stop
    Write-IRLog "Retrieved VM object: $($VM.Name)" -Level SUCCESS
}
catch {
    Write-IRLog "Failed to retrieve VM: $($_.Exception.Message)" -Level ERROR
    exit 1
}

# Containment Action 1: Isolate VM (remove network interface)
Write-IRLog "Isolating VM: Removing network interface..." -Level WARNING

try {
    # In production, this would actually disconnect the NIC
    # For demo purposes, we'll simulate it
    # $NIC = Get-AzNetworkInterface -ResourceId $VM.NetworkProfile.NetworkInterfaces[0].Id
    # Remove-AzNetworkInterfaceIpConfig -Name $NIC.IpConfigurations[0].Name -NetworkInterface $NIC -Force
    # Set-AzNetworkInterface -NetworkInterface $NIC

    Write-IRLog "[SIMULATED] VM network interface removed (VM isolated from network)" -Level SUCCESS
    $IncidentReport.ContainmentPhase.NetworkIsolation = @{
        Status    = 'Success'
        Timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        Action    = 'Network interface removed'
    }
}
catch {
    Write-IRLog "Failed to isolate VM network: $($_.Exception.Message)" -Level ERROR
    $IncidentReport.ContainmentPhase.NetworkIsolation = @{ Status = 'Failed'; Error = $_.Exception.Message }
}

# Containment Action 2: Terminate suspicious processes
Write-IRLog "Terminating suspicious processes..." -Level WARNING

$TerminateProcessScript = @'
$SuspiciousProcesses = Get-Process | Where-Object {
    $_.ProcessName -match "update" -or
    $_.CommandLine -match "encryptor" -or
    $_.CommandLine -match "locked"
}

foreach ($Process in $SuspiciousProcesses) {
    Write-Host "Terminating process: $($Process.ProcessName) (PID: $($Process.Id))"
    Stop-Process -Id $Process.Id -Force
}

Write-Host "Suspicious processes terminated"
'@

try {
    # In production, use Invoke-AzVMRunCommand
    # Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VirtualMachineName -CommandId 'RunPowerShellScript' -ScriptString $TerminateProcessScript

    Write-IRLog "[SIMULATED] Suspicious processes terminated (update.exe)" -Level SUCCESS
    $IncidentReport.ContainmentPhase.ProcessTermination = @{
        Status        = 'Success'
        Timestamp     = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        ProcessKilled = @('update.exe')
    }
}
catch {
    Write-IRLog "Failed to terminate processes: $($_.Exception.Message)" -Level ERROR
}

# Containment Action 3: Revoke active sessions
Write-IRLog "Revoking active sessions for compromised account..." -Level WARNING

$RevokeSessionsScript = @'
$CompromisedUsers = @('hacker', 'admin')

foreach ($User in $CompromisedUsers) {
    # Log off user sessions
    $Sessions = query user | Select-String $User
    if ($Sessions) {
        $SessionId = ($Sessions -split '\s+')[2]
        logoff $SessionId
        Write-Host "Logged off session for: $User (Session ID: $SessionId)"
    }
}
'@

Write-IRLog "[SIMULATED] Active sessions revoked for 'hacker' account" -Level SUCCESS
$IncidentReport.ContainmentPhase.SessionRevocation = @{
    Status    = 'Success'
    Timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    Accounts  = @('hacker')
}

Write-IRLog "Containment phase complete" -Level SUCCESS

# =======================
# PHASE 3: ERADICATION
# =======================

Write-Host "`n========================================" -ForegroundColor Red
Write-Host "PHASE 3: ERADICATION" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

Write-IRLog "Beginning eradication phase..." -Level INFO

# Eradication Action 1: Remove suspicious user accounts
Write-IRLog "Removing suspicious user accounts..." -Level WARNING

$RemoveAccountScript = @'
$SuspiciousAccounts = @('hacker', 'backdoor', 'test')

foreach ($Account in $SuspiciousAccounts) {
    $UserExists = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
    if ($UserExists) {
        Remove-LocalUser -Name $Account -ErrorAction SilentlyContinue
        Write-Host "Removed suspicious account: $Account"
    }
}
'@

Write-IRLog "[SIMULATED] Suspicious accounts removed: hacker" -Level SUCCESS
$IncidentReport.EradicationPhase.AccountRemoval = @{
    Status          = 'Success'
    Timestamp       = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    AccountsRemoved = @('hacker')
}

# Eradication Action 2: Remove persistence mechanisms
Write-IRLog "Removing persistence mechanisms..." -Level WARNING

$RemovePersistenceScript = @'
# Remove suspicious scheduled tasks
$SuspiciousTasks = Get-ScheduledTask | Where-Object {
    $_.TaskName -match "update" -or $_.TaskName -match "backup"
}
foreach ($Task in $SuspiciousTasks) {
    Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false
    Write-Host "Removed scheduled task: $($Task.TaskName)"
}

# Remove suspicious registry run keys
$RunKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($Key in $RunKeys) {
    $Values = Get-ItemProperty -Path $Key
    foreach ($Value in $Values.PSObject.Properties) {
        if ($Value.Value -match "update.exe" -or $Value.Value -match "C:\\Temp") {
            Remove-ItemProperty -Path $Key -Name $Value.Name -Force
            Write-Host "Removed registry persistence: $($Value.Name)"
        }
    }
}
'@

Write-IRLog "[SIMULATED] Persistence mechanisms removed (scheduled tasks, registry keys)" -Level SUCCESS
$IncidentReport.EradicationPhase.PersistenceRemoval = @{
    Status    = 'Success'
    Timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
}

# Eradication Action 3: Delete malware files (after forensic copy)
Write-IRLog "Deleting malware files (evidence preserved)..." -Level WARNING

Write-IRLog "[SIMULATED] Malware files deleted: C:\Windows\Temp\update.exe" -Level SUCCESS
$IncidentReport.EradicationPhase.MalwareRemoval = @{
    Status       = 'Success'
    Timestamp    = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
    FilesDeleted = @('C:\Windows\Temp\update.exe')
}

Write-IRLog "Eradication phase complete" -Level SUCCESS

# =======================
# PHASE 5: EVIDENCE COLLECTION
# =======================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PHASE 5: EVIDENCE COLLECTION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-IRLog "Collecting forensic evidence..." -Level INFO

# Evidence Collection 1: Export Windows Event Logs
Write-IRLog "Exporting Windows Event Logs..." -Level INFO

$ExportLogsScript = @"
`$EvidencePath = '$($IRConfig.EvidencePath)'
New-Item -ItemType Directory -Path `$EvidencePath -Force | Out-Null

`$Logs = @('Security', 'System', 'Application')
foreach (`$LogName in `$Logs) {
    `$ExportPath = Join-Path -Path `$EvidencePath -ChildPath "`$LogName-`$(Get-Date -Format 'yyyyMMdd-HHmmss').evtx"
    wevtutil export-log `$LogName `$ExportPath /overwrite:true
    Write-Host "Exported `$LogName log: `$ExportPath"
}
"@

Write-IRLog "[SIMULATED] Event logs exported to $($IRConfig.EvidencePath)" -Level SUCCESS

# Evidence Collection 2: Calculate file hashes
Write-IRLog "Computing cryptographic hashes of malware samples..." -Level INFO

$HashMalwareScript = @'
$MalwareFiles = @('C:\Windows\Temp\update.exe', 'C:\Users\Public\malware.dll')

foreach ($File in $MalwareFiles) {
    if (Test-Path $File) {
        $Hash = Get-FileHash -Path $File -Algorithm SHA256
        Write-Host "SHA256 ($File): $($Hash.Hash)"
    }
}
'@

Write-IRLog "[SIMULATED] Malware hashes calculated:" -Level SUCCESS
Write-IRLog "  update.exe: 7a2f3c8d9e1b4a6c5f8e2d1a9b7c4e3f2a1d8c7b6e5a4f3d2c1b9a8e7d6c5b4a3" -Level INFO

$IncidentReport.EvidencePhase.FileHashes = @{
    'update.exe' = '7a2f3c8d9e1b4a6c5f8e2d1a9b7c4e3f2a1d8c7b6e5a4f3d2c1b9a8e7d6c5b4a3'
}

# Evidence Collection 3: Memory dump (optional)
Write-IRLog "Memory dump collection skipped (requires VM access)" -Level INFO

Write-IRLog "Evidence collection complete" -Level SUCCESS

# =======================
# INCIDENT SUMMARY
# =======================

$IncidentReport.Status = 'Resolved'
$IncidentReport.EndTime = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "INCIDENT RESPONSE COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "Incident ID:      $($IncidentReport.IncidentId)"
Write-Host "VM:               $($IncidentReport.VirtualMachine)"
Write-Host "Start Time:       $($IncidentReport.StartTime)"
Write-Host "End Time:         $($IncidentReport.EndTime)"
Write-Host "Status:           $($IncidentReport.Status)" -ForegroundColor Green
Write-Host ""
Write-Host "Actions Taken:"
Write-Host "  [X] Network isolation"
Write-Host "  [X] Process termination"
Write-Host "  [X] Session revocation"
Write-Host "  [X] Account removal"
Write-Host "  [X] Persistence cleanup"
Write-Host "  [X] Evidence preservation"

# Export incident report
$ReportPath = Join-Path -Path $PSScriptRoot -ChildPath "IR-Report-$IncidentId.json"
$IncidentReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "`nIncident report saved: $ReportPath" -ForegroundColor Cyan
Write-IRLog "Incident response playbook complete" -Level SUCCESS

return $IncidentReport
