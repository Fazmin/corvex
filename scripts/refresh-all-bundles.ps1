<#
.SYNOPSIS
    Run all three bundle refresh scripts in sequence.

.DESCRIPTION
    Orchestrates the Windows ports of the three release-bundle refresh
    scripts (Exploit-DB, Nuclei, Wappalyzer). Use this before cutting a
    release - see RELEASE_PIPELINE.md step 2.

    Each step runs its companion .ps1 in this directory. If any step
    fails, the orchestrator stops and prints a summary. On success it
    prints a per-step elapsed-time table.

    Dependencies: whatever the individual scripts need (git, cargo,
    python with pyyaml).

.PARAMETER NucleiTag
    Optional nuclei-templates tag override. Defaults to the latest tag.

.PARAMETER WappalyzerRef
    Optional Wappalyzer git ref. Defaults to 'main'.

.PARAMETER IncludeVulnDb
    Also build the embedded NVD + EPSS snapshot via vulndb-builder. Off
    by default - this step takes 5-30 minutes and is network-heavy, so
    it doesn't belong in every iteration. Run it before cutting a real
    release so the binary ships with up-to-date CVE data.

.PARAMETER NvdApiKey
    NVD API key for the vulndb step. Without one NVD throttles to
    10 req/min; with one, 100 req/min. Falls back to NVD_API_KEY env
    var. Ignored unless -IncludeVulnDb is set.

.PARAMETER VulnDbFull
    Force a full vulndb rebuild instead of incremental. Ignored unless
    -IncludeVulnDb is set.

.PARAMETER ContinueOnError
    Run remaining steps even if an earlier one fails. Default is to
    stop at the first failure.

.EXAMPLE
    pwsh -File scripts\refresh-all-bundles.ps1

.EXAMPLE
    pwsh -File scripts\refresh-all-bundles.ps1 -NucleiTag v9.9.0

.EXAMPLE
    pwsh -File scripts\refresh-all-bundles.ps1 -IncludeVulnDb -NvdApiKey $env:NVD_API_KEY
#>

[CmdletBinding()]
param(
    [string]$NucleiTag,
    [string]$WappalyzerRef = 'main',
    [switch]$IncludeVulnDb,
    [string]$NvdApiKey,
    [switch]$VulnDbFull,
    [switch]$ContinueOnError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Hashtable splat passes named parameters reliably; array splat would
# pass them as positional and break on multi-arg cases.
$nucleiArgs = @{}
if ($NucleiTag) { $nucleiArgs.Tag = $NucleiTag }

$jobs = @(
    [pscustomobject]@{ Name = 'exploitdb';  Script = 'refresh-exploitdb-bundle.ps1';  Args = @{} },
    [pscustomobject]@{ Name = 'nuclei';     Script = 'refresh-nuclei-bundle.ps1';     Args = $nucleiArgs },
    [pscustomobject]@{ Name = 'wappalyzer'; Script = 'refresh-wappalyzer.ps1';        Args = @{ Ref = $WappalyzerRef } }
)

if ($IncludeVulnDb) {
    $vulndbArgs = @{}
    if ($NvdApiKey) { $vulndbArgs.ApiKey = $NvdApiKey }
    if ($VulnDbFull) { $vulndbArgs.Full = $true }
    $jobs += [pscustomobject]@{
        Name   = 'vulndb'
        Script = 'build-vulndb-snapshot.ps1'
        Args   = $vulndbArgs
    }
}

$bar = '=' * 70

$start   = Get-Date
$results = New-Object System.Collections.Generic.List[object]

Write-Host ''
Write-Host $bar -ForegroundColor Cyan
Write-Host ("Bundle refresh starting at {0}" -f $start.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan
Write-Host ("Steps: {0}" -f (($jobs | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Cyan
Write-Host $bar -ForegroundColor Cyan

for ($idx = 0; $idx -lt $jobs.Count; $idx++) {
    $job  = $jobs[$idx]
    $path = Join-Path $ScriptDir $job.Script
    if (-not (Test-Path -Path $path)) {
        throw "missing script: $path"
    }

    $cumulative = ((Get-Date) - $start).TotalSeconds
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host ('==> step {0}/{1}: [{2}] {3}  (T+{4:N1}s)' -f ($idx + 1), $jobs.Count, $job.Name, $job.Script, $cumulative) -ForegroundColor Cyan
    if ($job.Args.Count -gt 0) {
        $argStr = ($job.Args.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' '
        Write-Host "    args: $argStr"
    }
    Write-Host $bar -ForegroundColor Cyan

    $jobStart = Get-Date
    $ok       = $true
    $errMsg   = $null
    try {
        $splat = $job.Args
        & $path @splat
        if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
            $ok = $false
            $errMsg = "exit $LASTEXITCODE"
        }
    } catch {
        $ok     = $false
        $errMsg = $_.Exception.Message
        Write-Host ('[{0}] FAILED: {1}' -f $job.Name, $errMsg) -ForegroundColor Red
    }

    $elapsed = (Get-Date) - $jobStart
    $results.Add([pscustomobject]@{
        Name    = $job.Name
        Ok      = $ok
        Error   = $errMsg
        Elapsed = $elapsed
    })

    if ($ok) {
        Write-Host ('[{0}] done in {1:N1}s' -f $job.Name, $elapsed.TotalSeconds) -ForegroundColor Green
    } elseif (-not $ContinueOnError) {
        Write-Host ('[{0}] aborted after {1:N1}s - stopping' -f $job.Name, $elapsed.TotalSeconds) -ForegroundColor Red
        break
    }
}

$total = (Get-Date) - $start

Write-Host ''
Write-Host $bar
Write-Host 'Summary'
Write-Host $bar
foreach ($r in $results) {
    if ($r.Ok) {
        $status = 'OK  '
        $color  = 'Green'
    } else {
        $status = 'FAIL'
        $color  = 'Red'
    }
    $line = '  [{0}] {1,-12} {2,7:N1}s' -f $status, $r.Name, $r.Elapsed.TotalSeconds
    if ($r.Error) { $line += "  ($($r.Error))" }
    Write-Host $line -ForegroundColor $color
}
Write-Host ('  total:                 {0,7:N1}s' -f $total.TotalSeconds)

$failed = @($results | Where-Object { -not $_.Ok })
if ($failed.Count -gt 0) {
    exit 1
}
