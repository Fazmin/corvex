#!/usr/bin/env bash
# Refresh the bundled subset of nuclei-templates under
# program/databases/nuclei/. Run this manually between corvex releases.
#
# Filter policy (matches THIRD_PARTY_LICENSES.md):
#   - info.severity ∈ {critical, high}  OR
#   - info.tags contains `kev`
#
# The script:
#   1. Shallow-clones nuclei-templates at the tag passed as $1
#      (default: the latest release tag).
#   2. Walks every *.yaml and copies matching templates into
#      program/databases/nuclei/, preserving the upstream directory
#      layout (http/cves/2024/..., http/exposures/..., etc.).
#   3. Writes program/databases/nuclei/MANIFEST.toml with the upstream
#      tag, commit sha, and per-template file → source-path mapping.
#   4. Rewrites the "Upstream:" line in THIRD_PARTY_LICENSES.md.
#
# Dependencies: git, python3 with pyyaml (pip install pyyaml), rsync/cp.

set -euo pipefail

TAG="${1:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$REPO_ROOT/program/databases/nuclei"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if command -v python3 >/dev/null 2>&1 && python3 -c "import yaml" 2>/dev/null; then
    PY=(python3)
elif command -v py >/dev/null 2>&1 && py -3 -c "import yaml" 2>/dev/null; then
    # Windows Python launcher — preferred over the 'python' stub that
    # ships in default PATH and routes to the Microsoft Store.
    PY=(py -3)
elif command -v python >/dev/null 2>&1 && python -c "import yaml" 2>/dev/null; then
    PY=(python)
else
    echo "python with pyyaml is required (pip install pyyaml)" >&2
    exit 1
fi

if [ -z "$TAG" ]; then
    TAG="$(git ls-remote --tags --sort=-v:refname \
        https://github.com/projectdiscovery/nuclei-templates.git \
        | awk 'NR==1 {print $2}' | sed 's@refs/tags/@@; s@\^{}@@')"
fi
echo "==> refreshing bundle at tag $TAG"

git clone --depth 1 --branch "$TAG" \
    https://github.com/projectdiscovery/nuclei-templates.git \
    "$TMP/nuclei-templates"
COMMIT="$(git -C "$TMP/nuclei-templates" rev-parse HEAD)"

# Preserve project-owned files at the destination root (README.md,
# overlap.toml); wipe only the extracted template subtree + manifest.
mkdir -p "$DEST"
find "$DEST" -mindepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
rm -f "$DEST/MANIFEST.toml"

"${PY[@]}" - "$TMP/nuclei-templates" "$DEST" "$TAG" "$COMMIT" <<'PY'
import os, sys, shutil, pathlib, yaml

SRC, DEST, TAG, COMMIT = sys.argv[1:5]
SRC = pathlib.Path(SRC); DEST = pathlib.Path(DEST)

keep = []
for p in SRC.rglob("*.yaml"):
    # Only HTTP-protocol templates — skip workflows, network, etc.
    if "http" not in p.parts:
        continue
    try:
        with p.open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        continue
    if not isinstance(doc, dict):
        continue
    info = doc.get("info") or {}
    sev = str(info.get("severity", "")).lower()
    tags = info.get("tags", "")
    if isinstance(tags, str):
        tag_list = [t.strip() for t in tags.split(",")]
    elif isinstance(tags, list):
        tag_list = [str(t) for t in tags]
    else:
        tag_list = []
    if sev in ("critical", "high") or "kev" in tag_list:
        rel = p.relative_to(SRC)
        out = DEST / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, out)
        keep.append((str(rel).replace("\\", "/"), doc.get("id", "")))

manifest = DEST / "MANIFEST.toml"
with manifest.open("w", encoding="utf-8") as fh:
    fh.write(f'upstream_tag = "{TAG}"\n')
    fh.write(f'upstream_commit = "{COMMIT}"\n')
    fh.write(f'template_count = {len(keep)}\n\n')
    fh.write("[templates]\n")
    for rel, tid in sorted(keep):
        fh.write(f'"{rel}" = "{tid}"\n')

print(f"wrote {len(keep)} templates to {DEST}")
PY

echo "==> updating THIRD_PARTY_LICENSES.md upstream tag"
sed -i.bak -E \
    "s@^\\*\\*Upstream:\\*\\*.*nuclei-templates.*\$@**Upstream:** https://github.com/projectdiscovery/nuclei-templates (tag $TAG, commit $COMMIT)@" \
    "$REPO_ROOT/THIRD_PARTY_LICENSES.md" \
    || true
rm -f "$REPO_ROOT/THIRD_PARTY_LICENSES.md.bak"

echo "done"
