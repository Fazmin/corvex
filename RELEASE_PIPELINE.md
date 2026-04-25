# Release pipeline

How to cut a new corvex-rust (corvex-desktop) build, from "tree is
clean" to "installer is up on a GitHub Release". Read this before
shipping anything non-trivial — the dataset refresh step in
particular is easy to forget and will embarrass you when users
report "why is this CVE missing".

---

## TL;DR

```bash
# 1. make sure tree is clean and on the right commit
git status
git pull --ff-only

# 2. refresh bundled datasets if this is a real release
bash scripts/refresh-exploitdb-bundle.sh
bash scripts/refresh-nuclei-bundle.sh
bash scripts/refresh-wappalyzer.sh
git add program/databases/ && git commit -m "chore: refresh bundled datasets for release"

# 3. bump version if needed (see "When to bump" below)
# edit [workspace.package] version = "X.Y.Z" in Cargo.toml
# git add Cargo.toml Cargo.lock && git commit -m "chore: bump version to X.Y.Z"

# 4. tag
git tag vX.Y.Z
git push origin main --tags

# 5. build
cargo tauri build

# 6. upload target/release/bundle/{msi,nsis}/* to a GitHub Release
```

---

## Build commands

### Option A — full packaged installer (what you ship)

From the repo root:

```bash
cargo tauri build
```

This runs the full release pipeline:

1. `beforeBuildCommand` in `crates/corvex-desktop/tauri.conf.json`
   executes `npm run build` — compiles the React frontend to
   `crates/corvex-desktop/ui/dist/`.
2. `cargo build --release -p corvex-desktop` — compiles the Rust side
   with optimisations.
3. Tauri bundles the binary + `tauri.conf.json` resources (the
   Nuclei templates, the Exploit-DB snapshot, `THIRD_PARTY_LICENSES.md`,
   `corvex.conf.default`) into an installer.

Artefacts land under `target/release/`:

| Path | What it is |
| --- | --- |
| `target/release/corvex-desktop.exe` | Standalone Windows binary — no installer, no registry entries. |
| `target/release/bundle/msi/corvex-rust_X.Y.Z_x64_en-US.msi` | Windows MSI installer — the default distribution channel. |
| `target/release/bundle/nsis/corvex-rust_X.Y.Z_x64-setup.exe` | Windows NSIS installer — smaller, simpler. |

Each build stamps a fresh `CORVEX_BUILD_ID` (short git SHA, with a
`-dirty` suffix when the working tree has uncommitted changes).

### Option B — release binary only (dev iteration)

```bash
cargo build --release -p corvex-desktop
# -> target/release/corvex-desktop.exe
```

Fast when you just want to smoke-test a release-profile binary
without paying the installer-bundling cost. The binary still works
from the source tree — bundled datasets resolve via the `cwd`
candidate in the resource lookup, so `program/databases/...` is
found without the Tauri resource layout.

### Option C — dev run (no release profile)

```bash
cargo tauri dev
```

Reloads on frontend edits, keeps `cargo build` in `debug` profile,
gives you the full devtools experience. Not for release testing.

---

## Version stamping

Every build stamps four constants in `corvex-core` via `build.rs`.
They change automatically — you never edit them by hand.

| Constant | Source | Example |
| --- | --- | --- |
| `VERSION` | `[workspace.package] version` in `Cargo.toml` | `0.1.0` |
| `BUILD_ID` | `git rev-parse --short=10 HEAD` (+ `-dirty` if applicable) | `69ba372918` or `69ba372918-dirty` |
| `BUILD_DATE` | UTC date at build time | `20260424` |
| `BUILD_PROFILE` | `PROFILE` cargo env | `release` / `debug` |
| `FULL_VERSION` | `VERSION + "+" + BUILD_ID` | `0.1.0+69ba372918` |

Off-tree builds (tarball, source drop, no `.git/`) fall back to
`sde.<SOURCE_DATE_EPOCH>` or `d<YYYYMMDD>` for the build ID.

The frontend reads these via the `version_info` Tauri command
([api.ts](crates/corvex-desktop/ui/src/api.ts) `VersionInfo`
interface) — surface `full_version` in the title bar or About
dialog so every bug report is pinned to an identifiable build.

### Why not auto-bump semver on every build?

Because dirtying `Cargo.toml` on every `cargo build --release`
creates lock-file churn, confuses CI caches, and makes rebases
unpleasant. The approach above gives every release a unique,
verifiable identity (git SHA) without touching tracked files. Semver
still bumps manually — see below.

### When to bump the semver

Edit `[workspace.package] version` in the top-level `Cargo.toml`:

- **Patch** (`0.1.0 → 0.1.1`): bug fixes, dataset refreshes, doc
  updates, no API / behaviour change for users.
- **Minor** (`0.1.0 → 0.2.0`): new features, new views, new commands,
  new config keys. Backwards-compatible for existing users.
- **Major** (`0.1.0 → 1.0.0`): deliberate breaking change — renamed
  commands, removed views, incompatible config, persisted-DB schema
  break without a migration.

All crates inherit via `version.workspace = true`, so editing the
top-level is enough. Commit `Cargo.toml` + `Cargo.lock` together.

---

## Pre-release checklist

In this order. Each step is cheap; skipping the dataset refresh is
the one that bites.

### 1. Clean tree

```bash
git status
git pull --ff-only
```

Any uncommitted change produces a `…-dirty` build ID. That's fine
for a nightly, but a tagged release should come from a clean tree.

### 2. Refresh bundled datasets

These scripts pull fresh upstream data and commit a deterministic
snapshot under `program/databases/`. They require network access
and may take a few minutes.

```bash
bash scripts/refresh-exploitdb-bundle.sh   # Exploit-DB index (~12 MB)
bash scripts/refresh-nuclei-bundle.sh      # Nuclei critical/high/medium + kev
bash scripts/refresh-wappalyzer.sh         # Wappalyzer fingerprints
```

Each produces a `MANIFEST.toml` recording the upstream commit SHA
and refresh timestamp — commit the full output tree, not just the
`MANIFEST.toml`.

```bash
git add program/databases/
git diff --cached --stat   # sanity-check what changed
git commit -m "chore: refresh bundled datasets for vX.Y.Z"
```

Skipping this is the single most common "why is this release stale"
footgun. The bundled Exploit-DB snapshot is what ships to users —
if you don't refresh it, everyone gets whatever state the tree had
at the previous release.

### 3. Bump semver (if this is an actual release)

```bash
# edit Cargo.toml: version = "X.Y.Z"
cargo check -p corvex-desktop            # refresh Cargo.lock
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to X.Y.Z"
```

Nightly / internal builds skip this — the build ID alone identifies
them.

### 4. Run the verification suite

```bash
cargo test --workspace --exclude vulndb-builder
cd crates/corvex-desktop/ui && npm run build && cd ../../..
```

Nothing beyond green. Manual smoke test: launch
`target/release/corvex-desktop.exe`, expand a log4shell finding,
confirm the Exploit-DB block renders with the fresh snapshot.

### 5. Tag and push

```bash
git tag vX.Y.Z
git push origin main --tags
```

The tag triggers no workflow at the moment — push is informational.
The `update-worker-manifest.yml` action runs on every push to
`main` and re-stamps `program/.timestamp`; the Cloudflare Worker
publish step is optional (skips gracefully when the
`CF_WORKER_UPDATE_URL` / `CF_WORKER_UPDATE_TOKEN` secrets aren't
configured, so contributor forks don't see red checks).

### 6. Build installers

```bash
cargo tauri build
```

Takes several minutes. The resulting MSI / NSIS live under
`target/release/bundle/` as listed above.

### 7. Publish the GitHub Release

1. Open <https://github.com/Fazmin/nikto-rust/releases/new>.
2. Tag: `vX.Y.Z` (pick the tag you just pushed).
3. Release title: `corvex-desktop vX.Y.Z`.
4. Body: changelog + the build ID
   (`cargo run -p corvex-desktop --release -- --version` — or read
   `FULL_VERSION` from any tool that surfaces it — and paste the
   `0.1.0+<sha>` line so users can match a downloaded installer
   to a specific commit).
5. Upload both bundles from `target/release/bundle/`:
   - `corvex-rust_X.Y.Z_x64_en-US.msi`
   - `corvex-rust_X.Y.Z_x64-setup.exe`
   Optional: the raw `corvex-desktop.exe` for power users who don't
   want an installer.
6. Publish.

---

## Continuous integration

Two workflows live in [.github/workflows/](.github/workflows/):

- **docker-build-push.yaml** — builds and pushes a container image
  on `main`. No release gating — every push rebuilds.
- **update-worker-manifest.yml** — runs on every `main` push. Writes
  `program/.timestamp` (epoch of the last commit) and, if the
  optional secrets are set, POSTs the parsed version to a Cloudflare
  Worker so a public update endpoint can serve the latest version.
  The worker publish step **skips without failing** when the
  secrets aren't configured — fork checks stay green.

Neither workflow produces release installers today — that's still a
local `cargo tauri build`. If you want CI-built installers, add a
new workflow that runs on tag push (`on: push: tags: [v*]`) and
publishes the bundle to the corresponding GitHub Release.

---

## What's in each bundle

The installer ships:

- The `corvex-desktop.exe` binary.
- `program/databases/nuclei/` — bundled Tier-1 Nuclei templates
  (critical/high/medium + KEV, pinned via `MANIFEST.toml`).
- `program/databases/exploitdb/exploitdb.sqlite` +
  `MANIFEST.toml` — the Exploit-DB CSV index snapshot.
- `program/corvex.conf.default` — default config.
- `THIRD_PARTY_LICENSES.md` — attribution for all bundled data.

Not shipped, fetched on demand by the running app into the user's
`<app_data_dir>`:

- Exploit-DB source bodies (fetched per View source click from
  gitlab, cached under `<app_data_dir>/exploitdb/cache/`).
- Tier-2 Nuclei extras (downloaded via Databases → Nuclei templates
  → Expand coverage).
- NVD / EPSS VulnDB snapshot (downloaded via SCA → Update).

---

## Rollback

If a release is broken in the wild:

1. **Don't delete the tag** — someone may already have installed
   that build and pointing them at the same version number with
   different bytes is worse than leaving the bad build alone.
2. **Cut a patch release** immediately — `X.Y.Z+1` with the fix.
3. **Mark the bad GitHub Release as pre-release** so the "latest"
   link on the release page doesn't point at it.
4. Update `program/.timestamp` implicitly via the next push (the
   action handles it).

---

## Troubleshooting

**`cargo tauri build` fails on `npm run build`** — run
`cd crates/corvex-desktop/ui && npm install` first. The UI
`node_modules` is not committed.

**"could not determine which binary to run"** — you're running
`cargo run` on the desktop crate and there are two bins. Use
`cargo run --bin corvex-desktop` or rely on the
`default-run = "corvex-desktop"` key in
`crates/corvex-desktop/Cargo.toml`.

**Stale Exploit-DB index in the released MSI** — you forgot step 2.
There is no automated gate for this; the only fix is to make
"refresh datasets" a muscle-memory part of the checklist.

**`-dirty` suffix in the build ID of a release** — commit or stash
the working tree before running `cargo tauri build`. The stamp is
only recomputed on a rebuild; a `cargo clean` + rebuild from a
clean tree fixes it.

**GitHub Actions `update-worker-manifest` red** — if it's the
Cloudflare step, it's already fixed to skip on missing secrets. If
it's the timestamp step, read the log; common cause is a push from
`github-actions[bot]` which the workflow `if:` guard should skip
automatically.
