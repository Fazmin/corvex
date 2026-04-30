<#
.SYNOPSIS
    Build the embedded unified rules catalog (Nikto + ZAP + Burp).

.DESCRIPTION
    Produces program/rules/rules.sqlite, which corvex-desktop's
    build.rs picks up via include_bytes! and embeds into the binary.

    Internally invokes the `corvex-rules-builder` crate
    (cargo run --package corvex-rules-builder --release). The builder
    parses every rule source under rules-sources/{nikto,zap,burp}/
    and writes a unified SQLite catalog. The run is fully local
    (no network) and finishes in seconds on the bundled source set.

    After the snapshot is updated, rebuild corvex-desktop so the new
    bytes get baked into the binary:
        cargo build --release -p corvex-desktop

.PARAMETER SourcesPath
    Override the rules source directory. Defaults to rules-sources
    under the repo root.

.PARAMETER OutputPath
    Override the snapshot output path. Defaults to
    program/rules/rules.sqlite under the repo root, matching the
    layout of the vulndb and devicedb snapshots.

.PARAMETER FilterSource
    Limit ingestion to one or more sources (e.g. nikto, zap, burp).
    Repeatable.
#>

[CmdletBinding()]
param(
    [string]$SourcesPath,
    [string]$OutputPath,
    [string[]]$FilterSource
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

if (-not $SourcesPath) {
    $SourcesPath = Join-Path $RepoRoot 'rules-sources'
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $RepoRoot 'program\rules\rules.sqlite'
}

if (-not (Test-Path -Path $SourcesPath)) {
    throw "sources directory not found: $SourcesPath"
}

$snapshotDir = Split-Path -Parent $OutputPath
if ($snapshotDir) {
    New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
}

Write-Phase 'Building rules snapshot via corvex-rules-builder'
Write-Host "    Sources: $SourcesPath"
Write-Host "    Output : $OutputPath"
if ($FilterSource) {
    Write-Host ("    Filter : {0}" -f ($FilterSource -join ', '))
}
Write-Host ''

$builderArgs = @(
    'run', '--package', 'corvex-rules-builder', '--release', '--',
    '--sources', $SourcesPath,
    '--output',  $OutputPath
)
foreach ($src in $FilterSource) {
    $builderArgs += @('--filter-source', $src)
}

$buildStart = Get-Date
Push-Location $RepoRoot
try {
    & cargo @builderArgs
    if ($LASTEXITCODE -ne 0) {
        throw "corvex-rules-builder failed (exit $LASTEXITCODE)"
    }
} finally {
    Pop-Location
}
$buildElapsed = (Get-Date) - $buildStart

if (-not (Test-Path -Path $OutputPath)) {
    throw "snapshot was not produced at $OutputPath"
}

$dbBytes = (Get-Item -Path $OutputPath).Length
Write-Host ''
Write-Phase ("snapshot ready: {0} ({1:N0} bytes, {2:N1} MB)" -f $OutputPath, $dbBytes, ($dbBytes / 1MB))
Write-Host ("[rules] total elapsed: {0:N1}s" -f $buildElapsed.TotalSeconds) -ForegroundColor Green
Write-Host ''
Write-Host 'Next: rebuild the binary so include_bytes! picks up the new snapshot.'
Write-Host '      cargo build --release -p corvex-desktop'
Write-Host '      (or `cargo tauri build` for the full installer)'
