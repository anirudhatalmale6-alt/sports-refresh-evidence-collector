<#
    ssh-undo.ps1        REVOKE THE ACCESS ssh-setup.ps1 GRANTED
    ---------------------------------------------------------------
    Removes Anirudha's key and reverses only the changes ssh-setup.ps1
    recorded. Your own keys, rules and services are left alone.

    The single line that matters: removing the key line revokes my access
    immediately and completely. Everything else here is tidying up.

    Works even if the state file is missing - it will still remove the key.

    Run from an elevated PowerShell.
#>

[CmdletBinding()]
param(
    [string] $AuthFile = 'C:\ProgramData\ssh\administrators_authorized_keys',
    [string] $StateDir = 'C:\ProgramData\ssh\anirudha-40731033',
    # Also remove the OpenSSH Server Windows feature, if setup installed it.
    # Off by default: uninstalling a Windows capability is slow and may want a reboot.
    [switch] $RemoveOpenSSH,
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
$Marker = 'anirudha-freelancer-40731033'

function Remove-KeyLine {
    # Removes only lines containing the marker; every other line is preserved in order.
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

if ($env:OS -ne 'Windows_NT') { throw 'This script is for Windows.' }
$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an ELEVATED PowerShell (Run as administrator).' }

Write-Host ''
Write-Host 'Revoking SSH access - project 40731033'
Write-Host '--------------------------------------'

$state = $null
$statePath = Join-Path $StateDir 'state.json'
if (Test-Path $statePath) {
    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    Write-Host "  state file             : found (applied $($state.appliedUtc))"
} else {
    Write-Host '  state file             : not found - will still remove the key'
}

# --- 1. The key: this is the step that actually revokes access -------
if (Test-Path $AuthFile) {
    $stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
    if (-not $DryRun) {
        if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
        Copy-Item -Path $AuthFile -Destination (Join-Path $StateDir "administrators_authorized_keys.before-undo-$stamp.bak") -Force
    }
    $before = @(Get-Content $AuthFile | Where-Object { $_.Trim() -ne '' }).Count
    if ($DryRun) {
        $hit = @(Get-Content $AuthFile | Where-Object { $_ -like "*$Marker*" }).Count
        Write-Host "  [dry run] would remove $hit line(s), leaving $($before - $hit) of your key(s)"
    } else {
        $removed = Remove-KeyLine -Path $AuthFile -Marker $Marker
        $after   = @(Get-Content $AuthFile -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne '' }).Count
        Write-Host "  my key                 : removed $removed line(s)"
        Write-Host "  your keys remaining    : $after"

        # If setup created this file and nothing else is in it, remove the empty file.
        if ($after -eq 0 -and $state -and -not $state.authFileExistedBefore) {
            Remove-Item -Path $AuthFile -Force
            Write-Host '  authorized_keys        : file was created by setup and is now empty - deleted'
        }
    }
} else {
    Write-Host '  authorized_keys        : not present, nothing to remove'
}

# --- 2. Firewall rule, only if setup created it ----------------------
if ($state -and $state.firewallCreatedByUs -and $state.firewallRuleName) {
    if ($DryRun) { Write-Host "  [dry run] would delete firewall rule '$($state.firewallRuleName)'" }
    else {
        Remove-NetFirewallRule -Name $state.firewallRuleName -ErrorAction SilentlyContinue
        Write-Host "  firewall rule          : deleted '$($state.firewallRuleName)'"
    }
} else {
    Write-Host '  firewall rule          : not created by setup - left alone'
}

# --- 3. sshd service back to how it was ------------------------------
if ($state -and $state.serviceStartupBefore) {
    $want = $state.serviceStartupBefore
    $map  = @{ 'Auto' = 'Automatic'; 'Automatic' = 'Automatic'; 'Manual' = 'Manual'; 'Disabled' = 'Disabled' }
    $target = $map[[string]$want]
    if ($target) {
        if ($DryRun) { Write-Host "  [dry run] would set sshd startup back to $target" }
        else {
            Set-Service -Name sshd -StartupType $target -ErrorAction SilentlyContinue
            Write-Host "  sshd startup           : restored to $target"
        }
    }
    if ([string]$state.serviceStatusBefore -ne 'Running') {
        if ($DryRun) { Write-Host '  [dry run] would stop sshd (it was not running before)' }
        else {
            Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
            Write-Host '  sshd service           : stopped (it was not running before setup)'
        }
    } else {
        Write-Host '  sshd service           : was already running before setup - left running'
    }
} else {
    Write-Host '  sshd service           : no prior state recorded - left as is'
}

# --- 4. The Windows feature, opt-in only -----------------------------
if ($RemoveOpenSSH) {
    if ($state -and $state.capabilityInstalledByUs) {
        if ($DryRun) { Write-Host '  [dry run] would remove the OpenSSH Server feature' }
        else {
            $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
            if ($cap) { Remove-WindowsCapability -Online -Name $cap.Name | Out-Null }
            Write-Host '  OpenSSH Server feature : removed'
        }
    } else {
        Write-Host '  OpenSSH Server feature : was already installed before setup - left alone'
    }
} else {
    Write-Host '  OpenSSH Server feature : left installed (pass -RemoveOpenSSH to remove it)'
}

Write-Host ''
Write-Host 'Done. My key is gone, so my access is gone - regardless of the steps above.'
Write-Host "Backups and the state file are in: $StateDir"
Write-Host ''
