<#
.SYNOPSIS
    Refresh the bundled Wappalyzer technology dataset under
    crates/corvex-intel/data/wappalyzer/.

.DESCRIPTION
    Windows PowerShell port of scripts/refresh-wappalyzer.sh.

    Verifies the upstream license file is present, records the pinned
    ref + commit, normalises the file layout to what the Rust loader
    expects, and runs the fingerprint test suite as a sanity check.

    Dependencies: git, cargo, PowerShell 5.1+ (or pwsh 7+).

.PARAMETER Ref
    Upstream git ref (tag or commit SHA). Defaults to 'main'.
#>

[CmdletBinding()]
param(
    [string]$Ref = 'main'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$UpstreamRepo = 'https://github.com/HTTPArchive/wappalyzer.git'
$UpstreamName = 'HTTPArchive/wappalyzer'

$Root = (& git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or -not $Root) { throw 'git rev-parse --show-toplevel failed' }

$Dest = Join-Path $Root 'crates\corvex-intel\data\wappalyzer'
$Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ('corvex-wappalyzer-' + [System.Guid]::NewGuid().ToString('N'))

function Write-Phase {
    param([string]$Msg)
    $ts = (Get-Date).ToString('HH:mm:ss')
    Write-Host "[$ts] [refresh] $Msg" -ForegroundColor Cyan
}

try {
    $stepStart = Get-Date
    Write-Phase "cloning $UpstreamName @ $Ref into $Tmp"
    $cloneStart = Get-Date
    & git clone --depth 1 --branch $Ref $UpstreamRepo $Tmp 2>$null
    if ($LASTEXITCODE -ne 0) {
        # Fall back to a full clone so commit SHAs also work.
        if (Test-Path -Path $Tmp) {
            Remove-Item -Recurse -Force -Path $Tmp -ErrorAction SilentlyContinue
        }
        & git clone $UpstreamRepo $Tmp
        if ($LASTEXITCODE -ne 0) { throw 'git clone failed' }
        & git -C $Tmp checkout $Ref
        if ($LASTEXITCODE -ne 0) { throw "git checkout $Ref failed" }
    }
    Write-Host ("    clone done in {0:N1}s" -f ((Get-Date) - $cloneStart).TotalSeconds)

    $src = $null
    foreach ($candidate in 'src/technologies', 'technologies', 'src/data/technologies') {
        $p = Join-Path $Tmp $candidate
        if (Test-Path -Path $p -PathType Container) { $src = $p; break }
    }
    if (-not $src) { throw "[refresh] could not find technologies/ under $Tmp" }

    $catFile = $null
    foreach ($candidate in 'src/categories.json', 'src/data/categories.json', 'categories.json') {
        $p = Join-Path $Tmp $candidate
        if (Test-Path -Path $p -PathType Leaf) { $catFile = $p; break }
    }
    if (-not $catFile) { throw "[refresh] could not find categories.json under $Tmp" }

    $licenseFile = $null
    foreach ($candidate in 'LICENSE', 'LICENSE.md', 'License.md') {
        $p = Join-Path $Tmp $candidate
        if (Test-Path -Path $p -PathType Leaf) { $licenseFile = $p; break }
    }
    if (-not $licenseFile) { throw '[refresh] no LICENSE file found - aborting out of caution' }

    $commit = (& git -C $Tmp rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $commit) { throw 'git rev-parse HEAD failed' }
    $shortCommit = $commit.Substring(0, [Math]::Min(12, $commit.Length))

    Write-Phase "wiping previous dataset at $Dest"
    $techDir = Join-Path $Dest 'technologies'
    if (Test-Path -Path $techDir) { Remove-Item -Recurse -Force -Path $techDir }
    New-Item -ItemType Directory -Path $techDir -Force | Out-Null

    Write-Phase 'copying technologies/*.json'
    $jsonFiles = @(Get-ChildItem -Path $src -Filter '*.json' -File)
    $copied = 0
    foreach ($f in $jsonFiles) {
        Copy-Item -Path $f.FullName -Destination $techDir -Force
        $copied++
        if ($copied % 10 -eq 0 -or $copied -eq $jsonFiles.Count) {
            Write-Host ("    {0}/{1} copied" -f $copied, $jsonFiles.Count)
        }
    }

    Write-Phase 'copying categories.json'
    Copy-Item -Path $catFile -Destination (Join-Path $Dest 'categories.json') -Force

    Write-Phase 'recording upstream license'
    $today               = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
    $upstreamLicensePath = Join-Path $Dest 'UPSTREAM_LICENSE.md'

    # Built with -f (single-quoted heredoc) so backticks render literally.
    $header = @'
# Wappalyzer upstream — {0}

- **Source**: {1}
- **Pinned ref**: `{2}` (commit `{3}`)
- **Refreshed**: {4}

The upstream `LICENSE` is reproduced verbatim below. The corvex
bundle redistributes the technology data under its terms.

---

'@ -f $UpstreamName, $UpstreamRepo, $Ref, $shortCommit, $today

    $licenseBody = [System.IO.File]::ReadAllText($licenseFile)
    [System.IO.File]::WriteAllText(
        $upstreamLicensePath,
        $header + $licenseBody,
        [System.Text.UTF8Encoding]::new($false)
    )

    $techCount = (Get-ChildItem -Path $techDir -File | Measure-Object).Count
    Write-Phase "wrote $techCount technology files"

    Write-Phase 'running fingerprint tests against the new data'
    Write-Host '    cargo will print Compiling lines and test progress below.'
    $testStart = Get-Date
    Push-Location $Root
    try {
        # No Out-Null here - want to see cargo's Compiling / test status.
        & cargo test -p corvex-intel --lib fingerprint
        if ($LASTEXITCODE -ne 0) { throw "cargo test failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }
    Write-Host ("    tests done in {0:N1}s" -f ((Get-Date) - $testStart).TotalSeconds)

    Write-Host ''
    Write-Host ("[wappalyzer] total elapsed: {0:N1}s" -f ((Get-Date) - $stepStart).TotalSeconds) -ForegroundColor Green
    Write-Host 'Done.'
    Write-Host ''
    Write-Host "Pinned  : $UpstreamName@$Ref ($shortCommit)"
    Write-Host "Location: $Dest"
    Write-Host "Count   : $techCount technology files"
    Write-Host ''
    Write-Host 'Next:'
    Write-Host "  1. Review $upstreamLicensePath - ensure it still matches"
    Write-Host '     the attribution table in crates/corvex-intel/data/LICENSE_NOTES.md.'
    Write-Host '  2. Commit crates/corvex-intel/data/wappalyzer/.'
} finally {
    if (Test-Path -Path $Tmp) {
        Get-ChildItem -Path $Tmp -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
        Remove-Item -Recurse -Force -Path $Tmp -ErrorAction SilentlyContinue
    }
}
