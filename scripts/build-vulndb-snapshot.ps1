<#
.SYNOPSIS
    Build the embedded NVD + EPSS vulnerability database snapshot.

.DESCRIPTION
    Produces program/vulndb/snapshot.db.gz, which corvex-core's build.rs
    picks up via include_bytes! and embeds into the corvex-desktop binary.

    Internally invokes the `vulndb-builder` crate (cargo run --package
    vulndb-builder --release). On the first run this performs a full
    download from the NVD 2.0 API; on subsequent runs it only fetches
    CVEs modified since the existing snapshot's timestamp.

    Without an API key NVD limits you to 10 req/min (~30 min full run).
    With a key (free, request at https://nvd.nist.gov/developers/request-an-api-key)
    you get 100 req/min (~5 min full run).

    Dependencies: cargo, internet access. PowerShell 5.1+ (or pwsh 7+).

.PARAMETER ApiKey
    NVD API key. Falls back to the NVD_API_KEY environment variable.

.PARAMETER Full
    Force a full rebuild instead of incremental.

.PARAMETER OutputPath
    Override the snapshot output path. Defaults to
    program/vulndb/snapshot.db.gz under the repo root.
#>

[CmdletBinding()]
param(
    [string]$ApiKey,
    [switch]$Full,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Phase {
    param([string]$Msg)
    $ts = (Get-Date).ToString('HH:mm:ss')
    Write-Host "[$ts] ==> $Msg" -ForegroundColor Cyan
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir '..')).Path

if (-not $OutputPath) {
    $OutputPath = Join-Path $RepoRoot 'program\vulndb\snapshot.db.gz'
}
$snapshotDir = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null

if (-not $ApiKey -and $env:NVD_API_KEY) {
    $ApiKey = $env:NVD_API_KEY
}

Write-Phase 'Building vulndb snapshot via vulndb-builder'
Write-Host "    Output: $OutputPath"
if ($ApiKey) {
    Write-Host '    NVD API key: provided (100 req/min)'
} else {
    Write-Host '    NVD API key: none (10 req/min - this will take ~20-30 minutes)'
    Write-Host '                 set NVD_API_KEY env var or pass -ApiKey for faster runs.'
}
$incremental = (Test-Path -Path $OutputPath) -and -not $Full
if ($incremental) {
    Write-Host '    Mode: incremental (existing snapshot detected)'
} elseif ($Full) {
    Write-Host '    Mode: full (--Full forced)'
} else {
    Write-Host '    Mode: full (no existing snapshot)'
}
Write-Host ''

$builderArgs = @('run', '--package', 'vulndb-builder', '--release', '--', '--output', $OutputPath)
if ($ApiKey) { $builderArgs += @('--api-key', $ApiKey) }
if ($Full)   { $builderArgs += '--full'   }

$buildStart = Get-Date
Push-Location $RepoRoot
try {
    & cargo @builderArgs
    if ($LASTEXITCODE -ne 0) {
        throw "vulndb-builder failed (exit $LASTEXITCODE)"
    }
} finally {
    Pop-Location
}
$buildElapsed = (Get-Date) - $buildStart

if (-not (Test-Path -Path $OutputPath)) {
    throw "snapshot was not produced at $OutputPath"
}

$gzBytes = (Get-Item -Path $OutputPath).Length
Write-Host ''
Write-Phase ("snapshot ready: {0} ({1:N0} bytes, {2:N1} MB)" -f $OutputPath, $gzBytes, ($gzBytes / 1MB))
Write-Host ("[vulndb] total elapsed: {0:N1}s" -f $buildElapsed.TotalSeconds) -ForegroundColor Green
Write-Host ''
Write-Host 'Next: rebuild the binary so include_bytes! picks up the new snapshot.'
Write-Host '      cargo build --release -p corvex-desktop'
Write-Host '      (or `cargo tauri build` for the full installer)'
