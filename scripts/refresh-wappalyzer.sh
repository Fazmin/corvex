#!/usr/bin/env bash
#
# Refresh the bundled Wappalyzer technology dataset from the
# HTTPArchive/wappalyzer fork (MIT, actively maintained).
#
# Usage:
#   scripts/refresh-wappalyzer.sh [REF]
#
# REF is an optional git ref (tag or commit SHA). Defaults to `main`.
# After it finishes, commit the changes under
# `crates/corvex-intel/data/wappalyzer/`.
#
# The script is intentionally defensive: it verifies the license the
# upstream ships, records the pinned tag + commit, and normalises the
# file layout to what the Rust loader expects.

set -euo pipefail

REF="${1:-main}"
UPSTREAM_REPO="https://github.com/HTTPArchive/wappalyzer.git"
UPSTREAM_NAME="HTTPArchive/wappalyzer"

ROOT="$(git rev-parse --show-toplevel)"
DEST="$ROOT/crates/corvex-intel/data/wappalyzer"
TMP="$(mktemp -d -t corvex-wappalyzer.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

echo "[refresh] cloning $UPSTREAM_NAME @ $REF into $TMP"
git clone --depth 1 --branch "$REF" "$UPSTREAM_REPO" "$TMP" 2>/dev/null || {
  # Fall back to a full clone so commit SHAs also work.
  git clone "$UPSTREAM_REPO" "$TMP"
  git -C "$TMP" checkout "$REF"
}

# Locate the technologies + categories directories. Upstream moved the
# data under `src/technologies/` in some periods; handle both layouts.
SRC=""
for candidate in "src/technologies" "technologies" "src/data/technologies"; do
  if [[ -d "$TMP/$candidate" ]]; then
    SRC="$TMP/$candidate"
    break
  fi
done
if [[ -z "$SRC" ]]; then
  echo "[refresh] could not find technologies/ under $TMP" >&2
  exit 1
fi

CATEGORIES_FILE=""
for candidate in \
  "src/categories.json" \
  "src/data/categories.json" \
  "categories.json"; do
  if [[ -f "$TMP/$candidate" ]]; then
    CATEGORIES_FILE="$TMP/$candidate"
    break
  fi
done
if [[ -z "$CATEGORIES_FILE" ]]; then
  echo "[refresh] could not find categories.json under $TMP" >&2
  exit 1
fi

LICENSE_FILE=""
for candidate in "LICENSE" "LICENSE.md" "License.md"; do
  if [[ -f "$TMP/$candidate" ]]; then
    LICENSE_FILE="$TMP/$candidate"
    break
  fi
done
if [[ -z "$LICENSE_FILE" ]]; then
  echo "[refresh] no LICENSE file found — aborting out of caution" >&2
  exit 1
fi

COMMIT="$(git -C "$TMP" rev-parse HEAD)"
SHORT_COMMIT="${COMMIT:0:12}"

echo "[refresh] wiping previous dataset at $DEST"
rm -rf "$DEST/technologies"
mkdir -p "$DEST/technologies"

echo "[refresh] copying technologies/*.json"
cp -f "$SRC"/*.json "$DEST/technologies/"

echo "[refresh] copying categories.json"
cp -f "$CATEGORIES_FILE" "$DEST/categories.json"

echo "[refresh] recording upstream license"
cat > "$DEST/UPSTREAM_LICENSE.md" <<EOF
# Wappalyzer upstream — $UPSTREAM_NAME

- **Source**: $UPSTREAM_REPO
- **Pinned ref**: \`$REF\` (commit \`$SHORT_COMMIT\`)
- **Refreshed**: $(date -u +%Y-%m-%d)

The upstream \`LICENSE\` is reproduced verbatim below. The corvex
bundle redistributes the technology data under its terms.

---

EOF
cat "$LICENSE_FILE" >> "$DEST/UPSTREAM_LICENSE.md"

TECH_COUNT="$(ls "$DEST/technologies" | wc -l | tr -d ' ')"
echo "[refresh] wrote $TECH_COUNT technology files"

echo "[refresh] running fingerprint tests against the new data"
cargo test -p corvex-intel --lib fingerprint >/dev/null

cat <<EOF

Done.

Pinned  : $UPSTREAM_NAME@$REF ($SHORT_COMMIT)
Location: $DEST
Count   : $TECH_COUNT technology files

Next:
  1. Review \`$DEST/UPSTREAM_LICENSE.md\` — ensure it still matches
     the attribution table in \`crates/corvex-intel/data/LICENSE_NOTES.md\`.
  2. Commit \`crates/corvex-intel/data/wappalyzer/\`.
EOF
