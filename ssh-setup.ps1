<#
    ssh-setup.ps1        ONE-TIME SSH ACCESS SETUP
    ---------------------------------------------------------------
    Grants Anirudha (Freelancer project 40731033) key-only SSH access
    to this machine so the pipeline work can be done without RDP.

    SAFETY PROPERTIES
      - APPEND-ONLY on administrators_authorized_keys. Existing keys are
        never rewritten, reordered or removed. The file is backed up first.
      - Idempotent. Running it twice adds nothing the second time.
      - Records every change it makes to a state file, so ssh-undo.ps1
        can reverse exactly those changes and nothing else.
      - Does NOT change the OpenSSH DefaultShell, does NOT create or
        modify any user account, does NOT touch RDP, and does NOT
        disable password authentication (your choice, not mine).

    Run from an elevated PowerShell.
#>

[CmdletBinding()]
param(
    # Override only for testing. Defaults to the real Windows location.
    [string] $AuthFile = 'C:\ProgramData\ssh\administrators_authorized_keys',
    [string] $StateDir = 'C:\ProgramData\ssh\anirudha-40731033',
    # Report what would change, change nothing.
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

$Marker = 'anirudha-freelancer-40731033'
$PubKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHrGhJj1kEkOuki7Ti4oPyraXh817RFqYfAHpq9rMdDB anirudha-freelancer-40731033'

# ======================================================================
# Key-file handling. Append-only, idempotent, newline-safe.
# ======================================================================

function Test-KeyPresent {
    param([string]$Path, [string]$Marker)
    if (-not (Test-Path $Path)) { return $false }
    foreach ($line in (Get-Content -Path $Path -ErrorAction SilentlyContinue)) {
        if ($line -like "*$Marker*") { return $true }
    }
    return $false
}

function Add-KeyLine {
    <#
        Appends one key line. Never rewrites existing content.
        Handles the case where the existing file has no trailing newline -
        without this, the new key would be glued onto the end of the last
        existing key and BOTH would stop working.
        Returns: 'added' | 'already-present'
    #>
    param([string]$Path, [string]$Marker, [string]$KeyLine)

    if (Test-KeyPresent -Path $Path -Marker $Marker) { return 'already-present' }

    if (Test-Path $Path) {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -gt 0 -and $bytes[$bytes.Length - 1] -ne 10) {
            # No trailing newline: add one before appending.
            [System.IO.File]::AppendAllText($Path, "`r`n", (New-Object System.Text.ASCIIEncoding))
        }
    }
    # ASCII, no byte-order mark. A BOM in this file breaks sshd silently.
    [System.IO.File]::AppendAllText($Path, ($KeyLine + "`r`n"), (New-Object System.Text.ASCIIEncoding))
    return 'added'
}

function Remove-KeyLine {
    <#
        Removes only lines containing the marker. Every other line is
        preserved byte-for-byte in order.
        Returns the number of lines removed.
    #>
    param([string]$Path, [string]$Marker)

    if (-not (Test-Path $Path)) { return 0 }
    $lines = @(Get-Content -Path $Path -ErrorAction Stop)
    $keep  = @($lines | Where-Object { $_ -notlike "*$Marker*" })
    $removed = $lines.Count - $keep.Count
    if ($removed -gt 0) {
        $text = ''
        if ($keep.Count -gt 0) { $text = ($keep -join "`r`n") + "`r`n" }
        [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.ASCIIEncoding))
    }
    return $removed
}

# ======================================================================
# Everything below touches Windows. Skipped under -DryRun.
# ======================================================================

if ($env:OS -ne 'Windows_NT') { throw 'This script is for Windows.' }

$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an ELEVATED PowerShell (Run as administrator).' }

$state = [ordered]@{
    marker              = $Marker
    appliedUtc          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    authFile            = $AuthFile
    authFileExistedBefore = (Test-Path $AuthFile)
    authFileBackup      = ''
    keyAction           = ''
    capabilityStateBefore = ''
    capabilityInstalledByUs = $false
    serviceStartupBefore  = ''
    serviceStatusBefore   = ''
    firewallRuleName      = ''
    firewallCreatedByUs   = $false
}

Write-Host ''
Write-Host 'SSH access setup - project 40731033'
Write-Host '-----------------------------------'

# --- 1. OpenSSH Server feature --------------------------------------
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
if (-not $cap) { throw 'OpenSSH.Server capability not found on this Windows build.' }
$state.capabilityStateBefore = [string]$cap.State
Write-Host "  OpenSSH Server feature : $($cap.State)"
if ($cap.State -ne 'Installed') {
    if ($DryRun) { Write-Host '  [dry run] would install the OpenSSH Server feature' }
    else {
        Write-Host '  installing (this can take a minute)...'
        Add-WindowsCapability -Online -Name $cap.Name | Out-Null
        $state.capabilityInstalledByUs = $true
    }
}

# --- 2. sshd service -------------------------------------------------
$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($svc) {
    $state.serviceStatusBefore  = [string]$svc.Status
    $state.serviceStartupBefore = [string](Get-CimInstance Win32_Service -Filter "Name='sshd'").StartMode
    Write-Host "  sshd service           : $($svc.Status) / startup $($state.serviceStartupBefore)"
} else {
    Write-Host '  sshd service           : not present yet'
}
if (-not $DryRun) {
    Set-Service -Name sshd -StartupType Automatic
    if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
}

# --- 3. Firewall -----------------------------------------------------
$existing = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
            Where-Object {
                $p = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $p -and $p.Protocol -eq 'TCP' -and ($p.LocalPort -contains '22' -or $p.LocalPort -eq '22')
            } | Select-Object -First 1
if ($existing) {
    Write-Host "  firewall               : already allowed by rule '$($existing.Name)' (left alone)"
} else {
    $ruleName = 'sshd-anirudha-40731033'
    $state.firewallRuleName = $ruleName
    if ($DryRun) { Write-Host "  [dry run] would create inbound TCP 22 rule '$ruleName'" }
    else {
        New-NetFirewallRule -Name $ruleName -DisplayName 'OpenSSH Server (sshd) - Anirudha 40731033' `
            -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
        $state.firewallCreatedByUs = $true
        Write-Host "  firewall               : created rule '$ruleName'"
    }
}

# --- 4. The key ------------------------------------------------------
if (-not $DryRun) {
    New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
    $sshDir = Split-Path $AuthFile -Parent
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }

    if (Test-Path $AuthFile) {
        # Back up BEFORE touching it, and record the existing ACL for your records.
        $stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $backup = Join-Path $StateDir "administrators_authorized_keys.before-$stamp.bak"
        Copy-Item -Path $AuthFile -Destination $backup -Force
        $state.authFileBackup = $backup
        (icacls $AuthFile) 2>&1 | Set-Content -Path (Join-Path $StateDir "acl.before-$stamp.txt") -Encoding ASCII

        $before = @(Get-Content $AuthFile | Where-Object { $_.Trim() -ne '' }).Count
        Write-Host "  authorized_keys        : exists, $before key line(s), backed up"
    } else {
        Write-Host '  authorized_keys        : does not exist, will be created'
    }

    $state.keyAction = Add-KeyLine -Path $AuthFile -Marker $Marker -KeyLine $PubKey
    Write-Host "  my key                 : $($state.keyAction)"

    $after = @(Get-Content $AuthFile | Where-Object { $_.Trim() -ne '' }).Count
    Write-Host "  authorized_keys now    : $after key line(s)"

    # sshd REQUIRES a tight ACL on this file or it silently ignores every key in it.
    icacls $AuthFile /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null

    $state | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $StateDir 'state.json') -Encoding ASCII
} else {
    Write-Host '  [dry run] would back up authorized_keys, then APPEND one key line'
}

# --- 5. What I need from you -----------------------------------------
Write-Host ''
Write-Host 'CONNECTION DETAILS - send me these two lines'
Write-Host "  username  : $env:USERNAME"
Write-Host "  computer  : $env:COMPUTERNAME"
try {
    $ips = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }
           ).IPAddress -join ', '
    Write-Host "  local IPs : $ips"
} catch { }
try {
    $pub = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 8).ip
    Write-Host "  public IP : $pub"
} catch {
    Write-Host '  public IP : could not look it up - take it from your provider panel'
}
Write-Host ''
$listening = $false
try { $listening = [bool](Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue) } catch { }
Write-Host ("  sshd listening on 22   : {0}" -f $(if ($listening) { 'YES' } else { 'no - tell me and we will look' }))
Write-Host ''
Write-Host 'To revoke my access at any time, run ssh-undo.ps1 (one line, same as this).'
Write-Host ''
