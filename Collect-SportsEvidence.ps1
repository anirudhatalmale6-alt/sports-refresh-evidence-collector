<#
    Collect-SportsEvidence.ps1        READ-ONLY EVIDENCE COLLECTOR
    ------------------------------------------------------------------
    Gathers diagnostic evidence for the MLB / NFL refresh pipelines.

    IT DOES NOT:
      - start, stop, enable, disable or modify any scheduled task
      - run either pipeline
      - install anything, or touch the network
      - open, read or copy any credential file, token or key
      - write anywhere except its own output folder on the Desktop

    Every text artifact is passed through a redaction pass before it is
    written to disk. Over-redaction is deliberate: a false positive costs
    you nothing, a leaked token costs you plenty.

    Usage (defaults are fine):
      powershell -ExecutionPolicy Bypass -File .\Collect-SportsEvidence.ps1

    Review first, then zip:
      powershell -ExecutionPolicy Bypass -File .\Collect-SportsEvidence.ps1 -NoZip
#>

[CmdletBinding()]
param(
    # Words used to find the relevant scheduled tasks.
    [string[]] $TaskNameMatch = @('mlb','nfl','refresh','sheet','baseball','football','sport'),

    # Optional: project folders, if auto-discovery from the task definition misses them.
    [string[]] $ProjectPath = @(),

    # How many days of Task Scheduler event log to include.
    [int] $EventDays = 14,

    # How many lines from the END of each log file.
    [int] $LogTailLines = 300,

    # Where the output folder is created.
    [string] $OutputRoot = "$env:USERPROFILE\Desktop",

    # Leave the folder unzipped so you can inspect it first.
    [switch] $NoZip
)

$ErrorActionPreference = 'Continue'

# ----------------------------------------------------------------------
# Files we will NEVER open, at any size, for any reason.
# ----------------------------------------------------------------------
$SecretFilePatterns = @(
    '*credential*','*credentials*','*client_secret*','*clientsecret*',
    '*token*','*.pem','*.key','*.p12','*.pfx','*service_account*',
    '*serviceaccount*','*secret*','*.pickle','*.env','.env*','*apikey*','*api_key*'
)

# Only these extensions are ever read as text.
$ReadableExtensions = @('.log','.txt','.out','.err','.json.log')

function Test-IsSecretFile {
    param([string]$Name)
    foreach ($p in $SecretFilePatterns) {
        if ($Name -like $p) { return $true }
    }
    return $false
}

# ----------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------
$RedactionRules = @(
    @{ Name = 'PEM private key block'; Pattern = '(?s)-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----' }
    @{ Name = 'JSON private_key';      Pattern = '"private_key"\s*:\s*"(?:[^"\\]|\\.)*"' }
    @{ Name = 'JSON private_key_id';   Pattern = '"private_key_id"\s*:\s*"[^"]*"' }
    @{ Name = 'JSON client_secret';    Pattern = '"client_secret"\s*:\s*"[^"]*"' }
    @{ Name = 'JSON refresh_token';    Pattern = '"refresh_token"\s*:\s*"[^"]*"' }
    @{ Name = 'JSON access_token';     Pattern = '"access_token"\s*:\s*"[^"]*"' }
    @{ Name = 'Google OAuth token';    Pattern = 'ya29\.[A-Za-z0-9\-_\.]+' }
    @{ Name = 'Google API key';        Pattern = 'AIza[A-Za-z0-9\-_]{10,}' }
    @{ Name = 'Bearer header';         Pattern = '(?i)bearer\s+[A-Za-z0-9\-\._~\+/]+=*' }
    @{ Name = 'Basic auth header';     Pattern = '(?i)basic\s+[A-Za-z0-9\+/]{16,}=*' }
    @{ Name = 'key=value secret';      Pattern = '(?i)\b(api[_-]?key|apikey|token|secret|password|passwd|pwd|auth|credential)\b\s*[:=]\s*\S+' }
    @{ Name = 'URL userinfo';          Pattern = '(?i)://[^/\s:@]+:[^/\s@]+@' }
    @{ Name = 'Sheets spreadsheet id'; Pattern = '(?i)(/spreadsheets/d/|spreadsheet_?id\s*[:=]\s*[''"]?)[A-Za-z0-9\-_]{25,}' }
    @{ Name = 'Email address';         Pattern = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}' }
    # Catch-all net for anything token-shaped that the named rules missed.
    # '=' is deliberately NOT in the boundary checks, or "cached=<token>" escapes.
    @{ Name = 'Long opaque string';    Pattern = '(?<![A-Za-z0-9+/])[A-Za-z0-9+/_\-]{40,}={0,2}(?![A-Za-z0-9+/])' }
)

function Protect-Text {
    <#  Returns a hashtable: Text (redacted) and Hits (rule name -> count).  #>
    param([string]$Text)

    $hits = @{}
    if ([string]::IsNullOrEmpty($Text)) {
        return @{ Text = ''; Hits = $hits }
    }

    foreach ($rule in $RedactionRules) {
        $found = [regex]::Matches($Text, $rule.Pattern)
        if ($found.Count -gt 0) {
            $hits[$rule.Name] = $found.Count
            $Text = [regex]::Replace($Text, $rule.Pattern, "[REDACTED:$($rule.Name)]")
        }
    }
    return @{ Text = $Text; Hits = $hits }
}

# ----------------------------------------------------------------------
# Output folder + manifest
# ----------------------------------------------------------------------
$stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
$OutDir  = Join-Path $OutputRoot "sports-evidence-$stamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Manifest = New-Object System.Collections.ArrayList

function Add-Artifact {
    <#  Writes text to the output folder AFTER redaction and records it.  #>
    param(
        [string]$FileName,
        [string]$Text,
        [string]$Source = '(generated)'
    )

    $result = Protect-Text -Text $Text
    $path   = Join-Path $OutDir $FileName
    Set-Content -Path $path -Value $result.Text -Encoding UTF8

    $redactionSummary = '(none)'
    if ($result.Hits.Count -gt 0) {
        $parts = @()
        foreach ($k in ($result.Hits.Keys | Sort-Object)) { $parts += "$k x$($result.Hits[$k])" }
        $redactionSummary = ($parts -join '; ')
    }

    [void]$Manifest.Add([pscustomobject]@{
        File       = $FileName
        Source     = $Source
        Bytes      = (Get-Item $path).Length
        Redactions = $redactionSummary
    })

    Write-Host ("  wrote {0,-38} redactions: {1}" -f $FileName, $redactionSummary)
}

function Out-Str {
    <#  Renders any object to a plain string for capture.  #>
    param([Parameter(ValueFromPipeline = $true)] $InputObject)
    process { $InputObject | Format-List * | Out-String -Width 4000 }
}

Write-Host ""
Write-Host "Sports pipeline evidence collector - READ ONLY"
Write-Host "Output folder: $OutDir"
Write-Host ""

# ----------------------------------------------------------------------
# A. Host, clock and timezone
# ----------------------------------------------------------------------
Write-Host "[A] Host, clock and timezone"
$hostInfo = New-Object System.Text.StringBuilder
[void]$hostInfo.AppendLine("Collected (local) : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
[void]$hostInfo.AppendLine("Collected (UTC)   : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))")
[void]$hostInfo.AppendLine("Computer name     : $env:COMPUTERNAME")
[void]$hostInfo.AppendLine("Collector account : $env:USERNAME")
[void]$hostInfo.AppendLine("PowerShell        : $($PSVersionTable.PSVersion)")
try {
    $tz = Get-TimeZone
    [void]$hostInfo.AppendLine("Time zone         : $($tz.Id) / $($tz.DisplayName)")
    [void]$hostInfo.AppendLine("Supports DST      : $($tz.SupportsDaylightSavingTime)")
} catch {
    [void]$hostInfo.AppendLine("Time zone         : (Get-TimeZone unavailable) $((Get-WmiObject Win32_TimeZone).Caption)")
}
try {
    $os = Get-CimInstance Win32_OperatingSystem
    [void]$hostInfo.AppendLine("OS                : $($os.Caption) build $($os.BuildNumber)")
    [void]$hostInfo.AppendLine("Last boot         : $($os.LastBootUpTime)")
} catch { }
Add-Artifact -FileName 'A-host-and-clock.txt' -Text $hostInfo.ToString() -Source 'Get-Date / Get-TimeZone / Win32_OperatingSystem'

# ----------------------------------------------------------------------
# B. Python processes still running  (capture this before any reboot)
# ----------------------------------------------------------------------
Write-Host "[B] Running python processes"
$procText = ''
try {
    $procs = Get-Process -Name python,pythonw,py -ErrorAction SilentlyContinue |
             Select-Object Id, ProcessName, StartTime, CPU, Path, Responding
    if ($procs) { $procText = ($procs | Out-Str) }
    else { $procText = "No python/pythonw/py process is currently running." }
} catch { $procText = "Could not enumerate processes: $($_.Exception.Message)" }
Add-Artifact -FileName 'B-python-processes.txt' -Text $procText -Source 'Get-Process python,pythonw,py'

# ----------------------------------------------------------------------
# C. Scheduled tasks
# ----------------------------------------------------------------------
Write-Host "[C] Scheduled tasks"
$candidateTasks = @()
try {
    $all = Get-ScheduledTask -ErrorAction Stop
    foreach ($t in $all) {
        foreach ($w in $TaskNameMatch) {
            if ($t.TaskName -match $w -or $t.TaskPath -match $w) { $candidateTasks += $t; break }
        }
    }
} catch {
    Add-Artifact -FileName 'C0-scheduledtask-module-error.txt' `
                 -Text "Get-ScheduledTask failed: $($_.Exception.Message)`r`nFall back to: schtasks /query /v /fo LIST" `
                 -Source 'Get-ScheduledTask'
}

if ($candidateTasks.Count -eq 0) {
    Add-Artifact -FileName 'C1-tasks-summary.txt' `
                 -Text "No scheduled task matched: $($TaskNameMatch -join ', ')`r`nRe-run with -TaskNameMatch to widen the search." `
                 -Source 'Get-ScheduledTask'
} else {
    $summary = New-Object System.Text.StringBuilder
    foreach ($t in $candidateTasks) {
        [void]$summary.AppendLine("=== $($t.TaskPath)$($t.TaskName) ===")
        [void]$summary.AppendLine("State     : $($t.State)")
        [void]$summary.AppendLine("Author    : $($t.Author)")
        try {
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            [void]$summary.AppendLine("LastRunTime       : $($info.LastRunTime)")
            [void]$summary.AppendLine("LastTaskResult    : $($info.LastTaskResult)")
            [void]$summary.AppendLine("NextRunTime       : $($info.NextRunTime)")
            [void]$summary.AppendLine("NumberOfMissedRuns: $($info.NumberOfMissedRuns)")
        } catch {
            [void]$summary.AppendLine("Get-ScheduledTaskInfo failed: $($_.Exception.Message)")
        }
        foreach ($a in $t.Actions) {
            [void]$summary.AppendLine("Action Execute    : $($a.Execute)")
            [void]$summary.AppendLine("Action Arguments  : $($a.Arguments)")
            [void]$summary.AppendLine("Action WorkingDir : $($a.WorkingDirectory)")
        }
        [void]$summary.AppendLine("MultipleInstances : $($t.Settings.MultipleInstances)")
        [void]$summary.AppendLine("ExecutionTimeLimit: $($t.Settings.ExecutionTimeLimit)")
        [void]$summary.AppendLine("RunLevel          : $($t.Principal.RunLevel)")
        [void]$summary.AppendLine("LogonType         : $($t.Principal.LogonType)")
        [void]$summary.AppendLine("")
    }
    Add-Artifact -FileName 'C1-tasks-summary.txt' -Text $summary.ToString() -Source 'Get-ScheduledTask / Get-ScheduledTaskInfo'

    # Full definitions. Export-ScheduledTask returns XML text; it never contains a stored password.
    $i = 0
    foreach ($t in $candidateTasks) {
        $i++
        try {
            $xml = Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            Add-Artifact -FileName ("C2-task-{0:d2}-definition.xml" -f $i) -Text $xml `
                         -Source "Export-ScheduledTask $($t.TaskPath)$($t.TaskName)"
        } catch {
            Add-Artifact -FileName ("C2-task-{0:d2}-definition.txt" -f $i) `
                         -Text "Export failed: $($_.Exception.Message)" -Source 'Export-ScheduledTask'
        }
    }

    # Derive project folders from the task definitions themselves.
    foreach ($t in $candidateTasks) {
        foreach ($a in $t.Actions) {
            if ($a.WorkingDirectory) { $ProjectPath += $a.WorkingDirectory }
            if ($a.Arguments) {
                foreach ($m in [regex]::Matches($a.Arguments, '[A-Za-z]:\\[^"'']+')) {
                    $dir = Split-Path $m.Value -Parent
                    if ($dir) { $ProjectPath += $dir }
                }
            }
        }
    }
}

# ----------------------------------------------------------------------
# D. Task Scheduler operational event log
# ----------------------------------------------------------------------
Write-Host "[D] Task Scheduler event log (last $EventDays days)"
$evText = ''
try {
    $since  = (Get-Date).AddDays(-$EventDays)
    $events = Get-WinEvent -FilterHashtable @{
                  LogName   = 'Microsoft-Windows-TaskScheduler/Operational'
                  StartTime = $since
              } -ErrorAction Stop
    if ($candidateTasks.Count -gt 0) {
        $names  = ($candidateTasks | ForEach-Object { [regex]::Escape($_.TaskName) }) -join '|'
        $events = $events | Where-Object { $_.Message -match $names }
    }
    $evText = ($events | Select-Object TimeCreated, Id, LevelDisplayName, Message |
               Format-Table -AutoSize -Wrap | Out-String -Width 400)
    if (-not $evText.Trim()) { $evText = "No matching events in the last $EventDays days." }
} catch {
    $evText = "Could not read the log: $($_.Exception.Message)`r`n" +
              "If it is disabled, that is itself a finding - the history tab would be empty too."
}
Add-Artifact -FileName 'D-task-scheduler-events.txt' -Text $evText -Source 'Microsoft-Windows-TaskScheduler/Operational'

# ----------------------------------------------------------------------
# E. Project inventory  (metadata + hashes only - no source is copied)
# ----------------------------------------------------------------------
Write-Host "[E] Project inventory"
$ProjectPath = $ProjectPath | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
$inv      = New-Object System.Text.StringBuilder
$logFiles = New-Object System.Collections.ArrayList
$dataFiles = New-Object System.Collections.ArrayList

if ($ProjectPath.Count -eq 0) {
    [void]$inv.AppendLine("No project folder identified. Re-run with -ProjectPath 'C:\path\to\project'.")
} else {
    foreach ($root in $ProjectPath) {
        [void]$inv.AppendLine("=== $root ===")
        $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -notmatch '\\(\.git|__pycache__|site-packages|node_modules)\\' }
        foreach ($f in $files) {
            $secret = Test-IsSecretFile -Name $f.Name
            $hash   = ''
            if (-not $secret -and $f.Length -lt 20MB) {
                try { $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.Substring(0,16) } catch { }
            }
            $tag = ''
            if ($secret) { $tag = '  [CREDENTIAL-LIKE: metadata only, never opened, not hashed]' }
            [void]$inv.AppendLine(("{0,-19}  {1,12}  {2}  {3}{4}" -f `
                $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $f.Length, $hash, $f.FullName, $tag))

            if (-not $secret) {
                if ($ReadableExtensions -contains $f.Extension.ToLower()) { [void]$logFiles.Add($f) }
                if ($f.Extension.ToLower() -in @('.csv','.tsv')) { [void]$dataFiles.Add($f) }
            }
        }
        [void]$inv.AppendLine("")
    }
}
Add-Artifact -FileName 'E-project-inventory.txt' -Text $inv.ToString() -Source 'Get-ChildItem / Get-FileHash'

# ----------------------------------------------------------------------
# F. Log tails  (redacted)
# ----------------------------------------------------------------------
Write-Host "[F] Log tails"
if ($logFiles.Count -eq 0) {
    Add-Artifact -FileName 'F-logs-none.txt' `
                 -Text "No .log/.txt/.out/.err files found under the project folders. If nothing is being logged, that is a finding in itself." `
                 -Source '(none)'
} else {
    $recent = $logFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 12
    $n = 0
    foreach ($f in $recent) {
        $n++
        $body = ''
        try { $body = (Get-Content -Path $f.FullName -Tail $LogTailLines -ErrorAction Stop) -join "`r`n" }
        catch { $body = "Could not read: $($_.Exception.Message)" }
        $header = "SOURCE : $($f.FullName)`r`nSIZE   : $($f.Length) bytes`r`nMODIFIED: $($f.LastWriteTime)`r`nTAIL   : last $LogTailLines lines`r`n" + ('-' * 70) + "`r`n"
        Add-Artifact -FileName ("F-log-{0:d2}-{1}.txt" -f $n, $f.BaseName) -Text ($header + $body) -Source $f.FullName
    }
}

# ----------------------------------------------------------------------
# G. Output data files  (header + row count only - no rows are copied)
# ----------------------------------------------------------------------
Write-Host "[G] Output data files"
$dataText = New-Object System.Text.StringBuilder
if ($dataFiles.Count -eq 0) {
    [void]$dataText.AppendLine("No .csv/.tsv output files found under the project folders.")
} else {
    foreach ($f in ($dataFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 30)) {
        [void]$dataText.AppendLine("=== $($f.FullName) ===")
        [void]$dataText.AppendLine("Modified : $($f.LastWriteTime)")
        [void]$dataText.AppendLine("Size     : $($f.Length) bytes")
        try {
            $head = Get-Content -Path $f.FullName -TotalCount 1 -ErrorAction Stop
            [void]$dataText.AppendLine("Header   : $head")
            $rows = 0
            foreach ($line in [System.IO.File]::ReadLines($f.FullName)) { $rows++ }
            [void]$dataText.AppendLine("Rows     : $($rows - 1) (excluding header)")
        } catch {
            [void]$dataText.AppendLine("Could not read header: $($_.Exception.Message)")
        }
        [void]$dataText.AppendLine("")
    }
}
Add-Artifact -FileName 'G-output-files.txt' -Text $dataText.ToString() -Source 'header line and row count only'

# ----------------------------------------------------------------------
# H. Python environment
# ----------------------------------------------------------------------
Write-Host "[H] Python environment"
$envText = New-Object System.Text.StringBuilder
$pythons = @()
foreach ($root in $ProjectPath) {
    foreach ($rel in @('venv\Scripts\python.exe','.venv\Scripts\python.exe','env\Scripts\python.exe')) {
        $p = Join-Path $root $rel
        if (Test-Path $p) { $pythons += $p }
    }
}
$sys = Get-Command python -ErrorAction SilentlyContinue
if ($sys) { $pythons += $sys.Source }
$pythons = $pythons | Sort-Object -Unique

if ($pythons.Count -eq 0) {
    [void]$envText.AppendLine("No python interpreter found in the project folders or on PATH.")
} else {
    foreach ($p in $pythons) {
        [void]$envText.AppendLine("=== $p ===")
        try { [void]$envText.AppendLine((& $p -V 2>&1 | Out-String)) } catch { [void]$envText.AppendLine("version check failed: $($_.Exception.Message)") }
        $pip = Join-Path (Split-Path $p -Parent) 'pip.exe'
        if (Test-Path $pip) {
            try { [void]$envText.AppendLine((& $pip freeze 2>&1 | Out-String)) } catch { [void]$envText.AppendLine("pip freeze failed: $($_.Exception.Message)") }
        }
        [void]$envText.AppendLine("")
    }
}
Add-Artifact -FileName 'H-python-environment.txt' -Text $envText.ToString() -Source 'python -V / pip freeze (offline, reads installed metadata only)'

# ----------------------------------------------------------------------
# I. Credential files - METADATA ONLY, never opened
# ----------------------------------------------------------------------
Write-Host "[I] Credential file metadata (never opened)"
$credText = New-Object System.Text.StringBuilder
[void]$credText.AppendLine("Name, size and modification time only. No credential file is opened, read, hashed or copied.")
[void]$credText.AppendLine("The modification time is the point: a key rotated around the failure date is a prime suspect.")
[void]$credText.AppendLine("")
$found = $false
foreach ($root in $ProjectPath) {
    $c = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
         Where-Object { Test-IsSecretFile -Name $_.Name }
    foreach ($f in $c) {
        $found = $true
        [void]$credText.AppendLine(("{0,-19}  {1,10} bytes   {2}" -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'), $f.Length, $f.Name))
        [void]$credText.AppendLine("    folder: $($f.DirectoryName)")
    }
}
if (-not $found) { [void]$credText.AppendLine("No credential-like file found in the project folders.") }
Add-Artifact -FileName 'I-credential-metadata.txt' -Text $credText.ToString() -Source 'Get-ChildItem (names and timestamps only)'

# ----------------------------------------------------------------------
# J. Manifest
# ----------------------------------------------------------------------
Write-Host "[J] Manifest"
$manText = New-Object System.Text.StringBuilder
[void]$manText.AppendLine("Evidence manifest - $stamp")
[void]$manText.AppendLine("Every file in this folder, its source, and what was redacted from it.")
[void]$manText.AppendLine("")
[void]$manText.AppendLine(($Manifest | Format-Table -AutoSize -Wrap | Out-String -Width 400))
$manPath = Join-Path $OutDir 'MANIFEST.txt'
Set-Content -Path $manPath -Value $manText.ToString() -Encoding UTF8

# ----------------------------------------------------------------------
# Zip
# ----------------------------------------------------------------------
Write-Host ""
if ($NoZip) {
    Write-Host "Folder ready for review (not zipped):"
    Write-Host "  $OutDir"
} else {
    $zip = "$OutDir.zip"
    try {
        Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zip -Force -ErrorAction Stop
        Write-Host "Done. Review the folder, then attach the zip:"
        Write-Host "  folder: $OutDir"
        Write-Host "  zip   : $zip"
    } catch {
        Write-Host "Zip failed ($($_.Exception.Message)). The folder is still here: $OutDir"
    }
}
Write-Host ""
Write-Host "Read MANIFEST.txt first - it lists every file and every redaction."
Write-Host ""
