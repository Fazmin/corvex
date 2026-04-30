#!/usr/bin/env bash
# build-vulndb-snapshot.sh
#
# Downloads NVD + EPSS data and creates a compressed SQLite snapshot
# that gets embedded into the corvex binary at compile time.
#
# Run this once before building a release binary:
#   ./scripts/build-vulndb-snapshot.sh
#
# The resulting file is placed at program/vulndb/snapshot.db.gz
# and will be automatically picked up by the build.rs script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SNAPSHOT_DIR="$ROOT_DIR/program/vulndb"
SNAPSHOT_DB="$SNAPSHOT_DIR/snapshot.db"
SNAPSHOT_GZ="$SNAPSHOT_DIR/snapshot.db.gz"

echo "==> Building vulndb snapshot"
echo "    Output: $SNAPSHOT_GZ"

# Build and run a temporary Rust binary that populates the database
cd "$ROOT_DIR"

echo "==> Running vulndb population (this downloads NVD + EPSS data)..."
echo "    This may take 10-30 minutes depending on your connection."
echo ""

# Use cargo run with a simple inline to populate the DB
cargo run --package corvex --release -- \
    --host sca://noop \
    --vulndb-update now \
    --vulndb-path "$SNAPSHOT_DB" \
    2>&1 || true

if [ ! -f "$SNAPSHOT_DB" ]; then
    echo "ERROR: Snapshot database was not created at $SNAPSHOT_DB"
    echo "       You may need to run the NVD download manually."
    exit 1
fi

ORIG_SIZE=$(stat -c%s "$SNAPSHOT_DB" 2>/dev/null || stat -f%z "$SNAPSHOT_DB" 2>/dev/null || echo "unknown")
echo "==> Raw database: $ORIG_SIZE bytes"

echo "==> Compressing with gzip..."
gzip -9 -f "$SNAPSHOT_DB"

GZ_SIZE=$(stat -c%s "$SNAPSHOT_GZ" 2>/dev/null || stat -f%z "$SNAPSHOT_GZ" 2>/dev/null || echo "unknown")
echo "==> Compressed snapshot: $GZ_SIZE bytes"
echo ""
echo "Done! Rebuild corvex to embed the snapshot:"
echo "    cargo build --release"
