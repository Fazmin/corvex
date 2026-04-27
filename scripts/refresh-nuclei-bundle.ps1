<#
.SYNOPSIS
    Refresh the bundled subset of nuclei-templates under program/databases/nuclei/.

.DESCRIPTION
    Windows PowerShell port of scripts/refresh-nuclei-bundle.sh.

    Filter policy (matches THIRD_PARTY_LICENSES.md):
      - info.severity in { critical, high, medium }, OR
      - info.tags contains 'kev'

    Steps:
      1. Shallow-clones nuclei-templates at the requested tag (default:
         the latest release tag from `git ls-remote --tags`).
      2. Walks every *.yaml under http/ and copies matching templates
         into program/databases/nuclei/ preserving the upstream layout.
      3. Writes program/databases/nuclei/MANIFEST.toml.
      4. Rewrites the 'Upstream:' line in THIRD_PARTY_LICENSES.md.

    Dependencies: git, python with pyyaml (`pip install pyyaml`),
    PowerShell 5.1+ (or pwsh 7+).

.PARAMETER Tag
    nuclei-templates git tag to pin to. Defaults to the latest tag.
#>

[CmdletBinding()]
param(
    [string]$Tag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$Dest      = Join-Path $RepoRoot 'program\databases\nuclei'

# Pick the first python invocation that has pyyaml available.
# Returns a [pscustomobject] with .Exe and .Args (or $null if none work).
function Find-PythonWithYaml {
    $candidates = @(
        [pscustomobject]@{ Exe = 'py';      Args = @('-3') },
        [pscustomobject]@{ Exe = 'python3'; Args = @()     },
        [pscustomobject]@{ Exe = 'python';  Args = @()     }
    )
    foreach ($c in $candidates) {
        if (-not (Get-Command $c.Exe -ErrorAction SilentlyContinue)) { continue }
        $probeArgs = @()
        if ($c.Args.Count -gt 0) { $probeArgs += $c.Args }
        $probeArgs += @('-c', 'import yaml')
        try {
            & $c.Exe @probeArgs *> $null
        } catch {
            continue
        }
        if ($LASTEXITCODE -eq 0) { return $c }
    }
    return $null
}

$Py = Find-PythonWithYaml
if ($null -eq $Py) {
    throw 'python with pyyaml is required (pip install pyyaml)'
}
Write-Host ("==> using python: {0} {1}" -f $Py.Exe, ($Py.Args -join ' '))

function Write-Phase {
    param([string]$Msg)
    $ts = (Get-Date).ToString('HH:mm:ss')
    Write-Host "[$ts] ==> $Msg" -ForegroundColor Cyan
}

if (-not $Tag) {
    Write-Phase 'resolving latest nuclei-templates tag'
    $lsRemote = & git ls-remote --tags --sort=-v:refname `
        https://github.com/projectdiscovery/nuclei-templates.git
    if ($LASTEXITCODE -ne 0) { throw 'git ls-remote failed' }
    $first = ($lsRemote | Where-Object { $_ -match '\S' } | Select-Object -First 1)
    if (-not $first) { throw 'git ls-remote returned no tags' }
    $Tag = ($first -split '\s+')[1] -replace '^refs/tags/','' -replace '\^\{\}$',''
}
Write-Phase "refreshing bundle at tag $Tag"

$Tmp   = Join-Path ([System.IO.Path]::GetTempPath()) ('corvex-nuclei-' + [System.Guid]::NewGuid().ToString('N'))
$Clone = Join-Path $Tmp 'nuclei-templates'
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null

try {
    $stepStart = Get-Date

    Write-Phase "git clone --depth 1 --branch $Tag (~30 MB)"
    $cloneStart = Get-Date
    & git clone --depth 1 --branch $Tag https://github.com/projectdiscovery/nuclei-templates.git $Clone
    if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }
    Write-Host ("    clone done in {0:N1}s" -f ((Get-Date) - $cloneStart).TotalSeconds)

    $commit = (& git -C $Clone rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $commit) { throw 'git rev-parse HEAD failed' }

    # Preserve project-owned files at the destination root (README.md,
    # overlap.toml); wipe only the extracted template subtree + manifest.
    if (-not (Test-Path -Path $Dest)) {
        New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    }
    Get-ChildItem -Path $Dest -Directory -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force
    $manifestPath = Join-Path $Dest 'MANIFEST.toml'
    if (Test-Path -Path $manifestPath) { Remove-Item -Force -Path $manifestPath }

    # Inline python filter — kept close to the bash version's heredoc,
    # with progress prints so the long walk isn't silent.
    $pyScript = @'
import os, sys, shutil, pathlib, time, yaml

SRC, DEST, TAG, COMMIT = sys.argv[1:5]
SRC = pathlib.Path(SRC); DEST = pathlib.Path(DEST)

print("[py] enumerating *.yaml under http/ ...", flush=True)
candidates = [p for p in SRC.rglob("*.yaml") if "http" in p.parts]
total = len(candidates)
print(f"[py] {total} http templates to evaluate", flush=True)

keep = []
last_print = time.time()
for i, p in enumerate(candidates, 1):
    try:
        with p.open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        doc = None
    if isinstance(doc, dict):
        info = doc.get("info") or {}
        sev = str(info.get("severity", "")).lower()
        tags = info.get("tags", "")
        if isinstance(tags, str):
            tag_list = [t.strip() for t in tags.split(",")]
        elif isinstance(tags, list):
            tag_list = [str(t) for t in tags]
        else:
            tag_list = []
        if sev in ("critical", "high", "medium") or "kev" in tag_list:
            rel = p.relative_to(SRC)
            out = DEST / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, out)
            keep.append((str(rel).replace("\\", "/"), doc.get("id", "")))
    now = time.time()
    if now - last_print >= 2.0 or i == total:
        pct = (i / total) * 100 if total else 100
        print(f"[py]   {i}/{total} ({pct:5.1f}%) examined, {len(keep)} kept", flush=True)
        last_print = now

manifest = DEST / "MANIFEST.toml"
with manifest.open("w", encoding="utf-8") as fh:
    fh.write(f'upstream_tag = "{TAG}"\n')
    fh.write(f'upstream_commit = "{COMMIT}"\n')
    fh.write(f'template_count = {len(keep)}\n\n')
    fh.write("[templates]\n")
    for rel, tid in sorted(keep):
        fh.write(f'"{rel}" = "{tid}"\n')

print(f"[py] wrote {len(keep)} templates to {DEST}", flush=True)
'@

    $pyPath = Join-Path $Tmp 'filter_templates.py'
    [System.IO.File]::WriteAllText($pyPath, $pyScript, [System.Text.UTF8Encoding]::new($false))

    Write-Phase 'filtering templates (severity in {critical,high,medium} or tag=kev)'
    $filterStart = Get-Date
    $pyArgs = @()
    if ($Py.Args.Count -gt 0) { $pyArgs += $Py.Args }
    $pyArgs += @($pyPath, $Clone, $Dest, $Tag, $commit)
    & $Py.Exe @pyArgs
    if ($LASTEXITCODE -ne 0) { throw "python filter failed (exit $LASTEXITCODE)" }
    Write-Host ("    filter done in {0:N1}s" -f ((Get-Date) - $filterStart).TotalSeconds)

    Write-Phase 'updating THIRD_PARTY_LICENSES.md upstream tag'
    $licensePath = Join-Path $RepoRoot 'THIRD_PARTY_LICENSES.md'
    if (Test-Path -Path $licensePath) {
        $content = [System.IO.File]::ReadAllText($licensePath)
        $pattern = '(?m)^\*\*Upstream:\*\*.*nuclei-templates.*$'
        $replacement = "**Upstream:** https://github.com/projectdiscovery/nuclei-templates (tag $Tag, commit $commit)"
        $newContent = [regex]::Replace($content, $pattern, $replacement)
        if ($newContent -ne $content) {
            [System.IO.File]::WriteAllText($licensePath, $newContent, [System.Text.UTF8Encoding]::new($false))
        }
    }

    Write-Host ("[nuclei] total elapsed: {0:N1}s" -f ((Get-Date) - $stepStart).TotalSeconds) -ForegroundColor Green
} finally {
    if (Test-Path -Path $Tmp) {
        # Git on Windows drops read-only files into .git/objects/pack —
        # clear the attribute so Remove-Item doesn't fail.
        Get-ChildItem -Path $Tmp -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
        Remove-Item -Recurse -Force -Path $Tmp -ErrorAction SilentlyContinue
    }
}
