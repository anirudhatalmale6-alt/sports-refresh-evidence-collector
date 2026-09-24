# Test harness for the redaction pass inside Collect-SportsEvidence.ps1
# Loads the SAME code the client will run, then asserts no secret survives.

$ErrorActionPreference = 'Stop'

$all   = Get-Content (Join-Path $PSScriptRoot 'Collect-SportsEvidence.ps1') -Raw
$start = $all.IndexOf('$RedactionRules = @(')
$end   = $all.IndexOf('# Output folder + manifest')
if ($start -lt 0) { throw 'INSTRUMENT BROKEN: could not find $RedactionRules' }
if ($end   -lt 0) { throw 'INSTRUMENT BROKEN: could not find end marker' }
$section = $all.Substring($start, $end - $start)
Invoke-Expression $section

if (-not $RedactionRules -or $RedactionRules.Count -eq 0) { throw 'INSTRUMENT BROKEN: no rules loaded' }
if (-not (Get-Command Protect-Text -ErrorAction SilentlyContinue)) { throw 'INSTRUMENT BROKEN: Protect-Text not defined' }
Write-Host "instrument ok: $($RedactionRules.Count) rules, Protect-Text defined"

$secrets = [ordered]@{
  pem      = "-----BEGIN RSA PRIVATE KEY-----`nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ`n-----END RSA PRIVATE KEY-----"
  jsonpk   = 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDeadBeef'
  oauth    = 'ya29.a0AfH6SMBx3kQ9vLmNoPqRsTuVwXyZ1234567890abcdefg'
  apikeyG  = 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'
  jwt      = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4'
  apikeykv = 'sk_live_51H8xYzAbCdEfGhIjKlMnOp'
  pw       = 'Hunter2Hunter2'
  proxypw  = 'p4ssw0rd'
  sheetid  = '1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms'
  email    = 'mlb-pipeline@sheets-proj-4471.iam.gserviceaccount.com'
  refresh  = '1//04dXfGhIjKlMnOpQrStUvWxYz-L9kQwErTyUiOpAsDfGhJkL'
}

$dirty = @"
2026-09-23 14:52:01 INFO  starting mlb refresh run_id=a41f
2026-09-23 14:52:01 DEBUG loading $($secrets.pem)
2026-09-23 14:52:02 DEBUG creds={"type":"service_account","private_key":"$($secrets.jsonpk)","client_email":"$($secrets.email)","refresh_token":"$($secrets.refresh)"}
2026-09-23 14:52:03 DEBUG Authorization: Bearer $($secrets.jwt)
2026-09-23 14:52:03 DEBUG access token $($secrets.oauth)
2026-09-23 14:52:04 DEBUG GET https://statsapi.example.com/v1/schedule?api_key=$($secrets.apikeykv)
2026-09-23 14:52:04 DEBUG maps key $($secrets.apikeyG)
2026-09-23 14:52:05 DEBUG password = $($secrets.pw)
2026-09-23 14:52:05 DEBUG proxy https://svcuser:$($secrets.proxypw)@proxy.corp.local:3128
2026-09-23 14:52:06 INFO  writing https://docs.google.com/spreadsheets/d/$($secrets.sheetid)/edit#gid=0
2026-09-23 14:52:07 INFO  rows=412 games=15 elapsed=6.1s
2026-09-23 14:52:52 ERROR requests.exceptions.ReadTimeout: HTTPSConnectionPool(host=statsapi.example.com, port=443)
"@

$res = Protect-Text -Text $dirty
if ($null -eq $res -or $null -eq $res.Text) { throw 'INSTRUMENT BROKEN: Protect-Text returned nothing' }

Write-Host ''
Write-Host '---- rules that fired ----'
foreach ($k in ($res.Hits.Keys | Sort-Object)) { Write-Host ("  {0} x{1}" -f $k, $res.Hits[$k]) }

Write-Host ''
Write-Host '---- leak assertions (must all pass) ----'
$leaks = 0
foreach ($k in $secrets.Keys) {
  foreach ($piece in ($secrets[$k] -split "`n")) {
    $piece = $piece.Trim()
    if ($piece.Length -lt 12) { continue }
    if ($res.Text.Contains($piece)) { Write-Host "  LEAK [$k]: $piece"; $leaks++ }
    else { Write-Host "  ok   [$k] removed" }
  }
}

Write-Host ''
Write-Host '---- diagnostics that must SURVIVE ----'
$lost = 0
foreach ($must in @('starting mlb refresh','run_id=a41f','rows=412 games=15','ReadTimeout','statsapi.example.com','2026-09-23 14:52:52','HTTPSConnectionPool')) {
  if ($res.Text.Contains($must)) { Write-Host "  kept  $must" }
  else { Write-Host "  LOST  $must"; $lost++ }
}

Write-Host ''
Write-Host '---- redacted output ----'
Write-Host $res.Text
Write-Host ''
if ($leaks -eq 0 -and $lost -eq 0) { Write-Host "RESULT: PASS ($($secrets.Count) secrets removed, 7 diagnostics preserved)" }
else { Write-Host "RESULT: FAIL - leaks=$leaks lostDiagnostics=$lost"; exit 1 }
