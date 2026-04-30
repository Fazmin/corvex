<#
.SYNOPSIS
    Build the embedded SNMP device-signature catalog snapshot.

.DESCRIPTION
    Produces program/devicedb/devices.sqlite, which corvex-desktop's
    build.rs picks up via include_bytes! and embeds into the binary.

    Internally invokes the `corvex-devicedb-builder` crate
    (cargo run --package corvex-devicedb-builder --release). The
    builder writes three tables:

      * device_entry / device_clause / device_clause_pattern — the SNMP
        device-signature catalog, ingested from every YAML file under
        crates/corvex-devicedb/data/devices/.
      * iana_enterprise — the IANA Private Enterprise Numbers list,
        ingested from crates/corvex-devicedb/data/iana-enterprise-numbers.txt.
      * ieee_oui — the IEEE OUI registry (MA-L / MA-M / MA-S),
        ingested from crates/corvex-devicedb/data/ieee-ouidb.json.

    The run is fully local (no network) and finishes in a few seconds.

    After the snapshot is updated, rebuild corvex-desktop so the new
    bytes get baked into the binary:
        cargo build --release -p corvex-desktop

.PARAMETER SourcesPath
    Override the YAML source directory. Defaults to
    crates/corvex-devicedb/data/devices under the repo root.

.PARAMETER OutputPath
    Override the snapshot output path. Defaults to
    program/devicedb/devices.sqlite under the repo root, matching the
    layout of the vulndb snapshot.

.PARAMETER Verbose
    Pass through verbose logging from the builder.
#>

[CmdletBinding()]
param(
    [string]$SourcesPath,
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

if (-not $SourcesPath) {
    $SourcesPath = Join-Path $RepoRoot 'crates\corvex-devicedb\data\devices'
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $RepoRoot 'program\devicedb\devices.sqlite'
}

if (-not (Test-Path -Path $SourcesPath)) {
    throw "sources directory not found: $SourcesPath"
}

$snapshotDir = Split-Path -Parent $OutputPath
if ($snapshotDir) {
    New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
}

$yamlCount = (Get-ChildItem -Path $SourcesPath -Filter '*.yaml' -File -ErrorAction SilentlyContinue).Count
Write-Phase 'Building devicedb snapshot via corvex-devicedb-builder'
Write-Host "    Sources: $SourcesPath ($yamlCount YAML files)"
Write-Host "    Output : $OutputPath"
if ($VerbosePreference -eq 'Continue') {
    Write-Host '    Mode   : verbose'
}
Write-Host ''

$builderArgs = @(
    'run', '--package', 'corvex-devicedb-builder', '--release', '--',
    '--sources', $SourcesPath,
    '--output',  $OutputPath
)
if ($VerbosePreference -eq 'Continue') { $builderArgs += '--verbose' }

$buildStart = Get-Date
Push-Location $RepoRoot
try {
    & cargo @builderArgs
    if ($LASTEXITCODE -ne 0) {
        throw "corvex-devicedb-builder failed (exit $LASTEXITCODE)"
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
Write-Phase ("snapshot ready: {0} ({1:N0} bytes, {2:N1} KB)" -f $OutputPath, $dbBytes, ($dbBytes / 1KB))
Write-Host ("[devicedb] total elapsed: {0:N1}s" -f $buildElapsed.TotalSeconds) -ForegroundColor Green
Write-Host ''
Write-Host 'Next: rebuild the binary so include_bytes! picks up the new snapshot.'
Write-Host '      cargo build --release -p corvex-desktop'
Write-Host '      (or `cargo tauri build` for the full installer)'
