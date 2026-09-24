# sports-refresh-evidence-collector

A **read-only** diagnostic collector for a Windows-hosted Python sports-stats
refresh pipeline (MLB / NFL) that publishes to Google Sheets.

It gathers the evidence needed to work out *which layer* of such a pipeline
failed — scheduling, fetch, build, validation, publish or the Sheets push —
without changing anything and without ever touching a credential.

## What it does NOT do

- does not start, stop, enable, disable or modify any scheduled task
- does not run the pipeline
- does not install anything and makes no network calls
- does not open, read, copy or hash any credential file, token or key
- writes nowhere except its own timestamped output folder on the Desktop

## Redaction

Every text artifact is passed through a redaction pass before it is written to
disk: PEM key blocks, service-account JSON fields, OAuth / bearer tokens,
Google API keys, `key=value` secrets, URL userinfo, spreadsheet IDs, email
addresses, plus a catch-all for anything else token-shaped.

Over-redaction is deliberate. A false positive costs nothing; a leaked token
costs plenty.

`Test-Redaction.ps1` loads the same rules out of the collector and asserts that
a synthetic dirty log loses all of its secrets while keeping the diagnostic
content. It fails loudly if the rules do not load, because a null result
otherwise reads as "no secrets found".

## Usage

```powershell
# review-only: leaves the folder unzipped so you can inspect it first
powershell -ExecutionPolicy Bypass -File .\Collect-SportsEvidence.ps1 -NoZip

# normal run: produces a folder plus a zip on the Desktop
powershell -ExecutionPolicy Bypass -File .\Collect-SportsEvidence.ps1
```

Read `MANIFEST.txt` in the output folder first — it lists every file collected,
where it came from, and exactly what was redacted from it.

## Tests

```powershell
pwsh -NoProfile -File .\Test-Redaction.ps1
```

Contains no configuration, hostnames, credentials or data belonging to any
client.
