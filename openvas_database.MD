# OpenVAS database integration

End-to-end design and operations doc for the `openvas-port` rule source — a
clean-room transpiler that turns the **Greenbone OpenVAS Community Feed**
(~95k NASL files) into native Rust-evaluated detection rules in
`rules.sqlite`.

**Current state (latest rebuild):** 831 transpiled rules, 100% executable,
0 invalid JSON. Total catalog now 8,381 rules across all four sources.

---

## 1. Why this exists

Corvex-rust's catalog (`program/rules/rules.sqlite`) consolidates every
detection rule the runtime can fire. Before this work the catalog drew from
three upstream sources — Nikto, OWASP ZAP, Burp BChecks — covering ~7,500
web-focused rules. The OpenVAS Community Feed adds another ~95k VTs that
Greenbone maintains for service / version / CVE detection, complementing
the web-only sources with banner / TLS / multi-step probes.

OpenVAS ships these as NASL scripts, not data. NASL is a full DSL with
runtime control flow; you can't just transpile a NASL file like you would
a YAML rule. The integration's job is to recognise *the conservative
subset* of NASL files whose detection logic is fully expressed by literal
facts (CVE / OID / regex / port / CPE) and emit equivalent `MatchSpec`
rules.

---

## 2. Licensing

Both corvex-rust and the OpenVAS Community Feed are **GPL-2.0-only**, so
copyleft compatibility is not the constraint. The transpiler still
operates under a clean-room policy because:

1. **Provenance hygiene.** Each emitted rule cites the OpenVAS OID and any
   CVE / advisory URL the NASL referenced. A reviewer can audit any
   finding back to a primary source without reading NASL.
2. **Bug-surface isolation.** Detection bugs in the upstream feed don't
   ride along — our matcher is independently authored.
3. **Relicensing optionality.** If the project ever moves to a permissive
   license, the transpiler's narrow rule (regex literals are *facts*,
   defended by NVD-record byte-equivalence) is the only NASL-derived
   surface that needs re-evaluating, instead of all 831 rules.

The full policy is at
[crates/corvex-feed-harvest/LICENSE_NOTES.md](crates/corvex-feed-harvest/LICENSE_NOTES.md).

> ### Critical: Tenable Nessus plugins are NOT compatible
>
> The user's machine had a `corvexdb/plugins/` folder containing
> 238k `.nasl` files at one point. Those were Tenable Nessus plugins
> (different fork of NASL since the OpenVAS/Nessus split in 2005),
> licensed under restrictive Tenable commercial terms. The transpiler
> **must not** consume them — license violation, not just
> license-compatibility risk. The harvester only points at the
> Greenbone Community Feed (`rsync://feed.community.greenbone.net/...`)
> by default.

---

## 3. Pipeline architecture

```
                         ┌──────────────────────────────┐
                         │  Greenbone Community Feed    │
                         │  rsync://feed.community...   │
                         │  (95k NASL files, GPL-2.0)   │
                         └──────────────┬───────────────┘
                                        │ rsync (Docker fallback)
                                        ▼
                         ┌──────────────────────────────┐
                         │ program/feed-cache/openvas/  │
                         │ (gitignored, ~485 MB)        │
                         └──────────────┬───────────────┘
                                        │ corvex-feed-harvest transpile
                                        ▼
                ┌────────────────────────────────────────────────┐
                │ rules-sources/openvas-port/                    │
                │   _transpiled/<family>/<oid>.json (auto)       │
                │   service/, cms/, appserver/, … (hand-authored)│
                └─────────────────┬──────────────────────────────┘
                                  │ corvex-rules-builder
                                  ▼
                  ┌──────────────────────────────┐
                  │  program/rules/rules.sqlite  │ ← embedded into desktop binary
                  │  (8,381 rules)               │
                  └──────────────────────────────┘
```

Three crates collaborate:

| Crate | Role | Path |
|---|---|---|
| `corvex-feed-harvest` | Dev-only — sync feed, transpile NASL, lint | [crates/corvex-feed-harvest/](crates/corvex-feed-harvest/) |
| `corvex-rules-builder` | Production — ingest all sources into SQLite | [crates/corvex-rules-builder/](crates/corvex-rules-builder/) |
| `corvex-rules` | Production — runtime that loads + evaluates `MatchSpec` | [crates/corvex-rules/](crates/corvex-rules/) |

The `corvex-feed-harvest` crate **never enters the desktop binary's
dependency graph**. It's a developer tool. The runtime sees only the SQLite
catalog produced by `corvex-rules-builder`.

---

## 4. The harvester (`corvex-feed-harvest`)

Four subcommands, all dev-only.

### 4.1 `sync` — pull the feed

```
cargo run -p corvex-feed-harvest -- sync
```

Wraps rsync against the Greenbone Community Feed at
`rsync://feed.community.greenbone.net/community/vulnerability-feed/22.04/vt-data/nasl/`,
landing files in `program/feed-cache/openvas/` (gitignored).

**Resilience features:**

- `--partial --append-verify --timeout=60` so a Docker daemon cycle or
  network glitch doesn't lose progress. Re-running `sync` resumes from
  where the last run stopped and re-verifies each partial file's checksum.
- **Docker fallback** — if `rsync` isn't on PATH (typical Windows clean
  install), the harvester transparently runs rsync inside an Alpine
  container via `docker run --rm -v <cache>:/cache instrumentisto/rsync-ssh`.
  Detection at [sync.rs:84-92](crates/corvex-feed-harvest/src/sync.rs#L84-L92)
  uses `docker --version` (no daemon required) so the existence check is
  fast and reliable.
- Windows path normalisation — Docker bind-mounts get `D:\foo\bar`
  converted to `D:/foo/bar` automatically.

Use `--dry-run` to print the rsync command without invoking it.

### 4.2 `scaffold` — emit hand-authoring stubs

```
cargo run -p corvex-feed-harvest -- scaffold --family wordpress --limit 25
```

For NASLs the transpiler can't handle, this emits JSON stubs to
`rules-sources/openvas-port/_scaffolds/<oid>.json` carrying the harvested
**facts only** — OID, CVE list, family, default ports, CPE, advisory URLs
— plus a `_TODO` block. A human author moves the file out of `_scaffolds/`
and fills in the `match_spec` against the **vendor advisory** (not the
NASL).

The parser at
[crates/corvex-rules-builder/src/parsers/openvas_port.rs:159](crates/corvex-rules-builder/src/parsers/openvas_port.rs#L159)
explicitly skips `_scaffolds/` so half-written files never reach
`rules.sqlite`.

### 4.3 `transpile` — bulk auto-emit

```
cargo run -p corvex-feed-harvest -- transpile
```

Runs the conservative transpiler in parallel via rayon (~1,200-1,500
files/sec on 12 cores; ~70s to process all 95k files). Emits to
`rules-sources/openvas-port/_transpiled/<family>/<oid>.json`, disjoint
from hand-authored rules. Re-runnable; safe to wipe.

`--force` overwrites existing transpiled files.

### 4.4 `lint` — clean-room enforcement

```
cargo run -p corvex-feed-harvest -- lint
```

For every hand-authored rule in `rules-sources/openvas-port/` whose
`provenance.openvas_oid` references a NASL in the feed cache, fails the
build if any ≥6-byte string under `match_spec` co-occurs verbatim in the
NASL body. Catches accidental copy-paste of NASL detection-logic strings
into hand-authored rules. Skips structural fields (`id`/`kind`/`step`)
and the provenance/references blocks where overlap is expected.

---

## 5. The transpiler

Conservative by design — it emits a `MatchSpec` only for VTs whose entire
detection logic is reducible to **literal facts** (regex pattern, URL
path, port number, header name). Anything richer is rejected so it
doesn't produce wrong rules.

### 5.1 Eligibility shapes (in order of evaluation)

Each NASL is run through these shape recognisers in order; the first
match owns the OID. Order matters — earlier recognisers produce
more-informative rules.

| # | Shape | Family | What it captures |
|---|---|---|---|
| 1 | **Dependency chain** | Web/Web-app | Vuln VTs that route through `get_app_port(cpe:CPE)` + `script_dependencies` to a fingerprint VT. Emits a 2-step rule (fingerprint → vuln-confirm). |
| 2 | **HTTP multi-step** | Web/Web-app | 2-3 distinct literal `http_get` paths in source order. Each step's status + body matchers AND-join. |
| 3 | **Product detection** | "Product detection" | Standalone fingerprint VTs: single `http_get` literal + single `egrep` + `register_product()`. Severity always `info`. |
| 4 | **HTTP header banner** | Web/Web-app | `Server:` / `X-Powered-By:` / `WWW-Authenticate:` regex matches against response headers. |
| 5 | **HTTP multi-pattern** | Web/Web-app | Single `http_get` + 2-3 AND-joined `egrep` patterns. |
| 6 | **HTTP banner version** | Web Servers | Single `http_get` + single `egrep` (the original "fingerprint by body regex" pattern). |
| 7 | **CGI / PHP-app banner** | Web app abuses / cgi-abuses | Same shape as banner version, different family filter. |
| 8 | **Service banner** | Service detection | `script_require_ports(N)` + single `egrep` against banner. **Schema-only — Phase C runtime not yet shipped.** |
| 9 | **TLS version / cipher** | SSL and TLS | Single negotiated protocol or cipher-family literal. **Schema-only — Phase C runtime not yet shipped.** |

### 5.2 URL extraction shapes

`resolve_first_http_get_path` and `collect_http_get_paths` recognise four
common idioms for the URL:

```
http_get(item:"/literal", ...)                       // direct
http_get(item:string(dir, "/literal", ...), ...)     // dir-iterator
http_get(item:dir + "/literal", ...)                 // NASL `+` concat
URL = string(dir, "/literal");                       // var indirection
http_get(item:URL, ...)                              //   (chases variable)
```

Strict literal-extraction is the safety property. Anything richer
(`strcat`, `raw_string`, runtime payload variables in the URL) is
rejected so the transpiler can't fabricate a wrong URL.

### 5.3 Pattern extraction shapes

`collect_egrep_patterns_with_offsets` captures:

| NASL idiom | Treated as |
|---|---|
| `egrep(pattern:"REGEX", string:res)` | regex match |
| `eregmatch(pattern:"REGEX", ...)` | regex match |
| `pregmatch(pattern:"REGEX", ...)` | regex match |
| `ereg(pattern:"REGEX", ...)` | regex match |
| `"literal" >< var` (NASL substring-contains) | `regex::escape("literal")` body match |
| `var >< "literal"` (same, reversed) | `regex::escape("literal")` body match |

Substring literals get `regex::escape`'d so the runtime matcher checks
byte-containment rather than treating the literal as a regex pattern.

Patterns under 4 bytes are dropped to reduce false hits from common
operators like `"/" >< path`.

Every pattern is validated via `regex::Regex::new()` before emit — an
unparseable pattern would silently drop the rule at lowering time, so we
reject upfront.

### 5.4 Disqualifiers (`has_disqualifying_helpers`)

Rejected up-front:

- `http_get(item:strcat(...))` / `http_get(item:raw_string(...))` —
  runtime URL construction we can't recover.
- `ssl_handshake` / `openvas_get_kb_item` — needs real protocol replay
  or stateful KB.
- Local-Security-Check helpers (`isdpkgvuln`, `isrpmvuln`,
  `isfreebsdvuln`, `isgentoovuln`, `isbsdvuln`, `isnaslvuln`) — needs
  authenticated host scan.
- Phase D probes (`smb_session_setup`, `nasl_ssh_request_exec`,
  `snmp_get`, `snmpv3_*`).
- Family-level skip: any `Local Security Checks` family (Fedora /
  Debian / SuSE / Ubuntu / CentOS / Gentoo / FreeBSD / Oracle Linux /
  Red Hat / Mandrake / Amazon Linux / Mac OS X) — saves ~60k pointless
  recogniser attempts.

### 5.5 Severity inference

Default per-shape severity is overridden by NASL category:

| `script_category` | Severity |
|---|---|
| `ACT_DESTRUCTIVE_ATTACK` | critical |
| `ACT_DENIAL` / `ACT_KILL_HOST` / `ACT_FLOOD` | high |
| `ACT_ATTACK` | high |
| `ACT_MIXED_ATTACK` | medium |
| `ACT_GATHER_INFO` / `ACT_SETTINGS` | info |
| anything else | medium |

CVE-bearing rules cap *upward* to ≥ medium (a security bulletin exists,
"info" is wrong).

### 5.6 Performance characteristics

Walked single-threaded (rayon-incompatible iterator state), then
classified in parallel. Latest run on 95,086 files / 12-core release
build:

```
[transpile] indexed 95086 .nasl files in 0.08s
[transpile] processed 95086 files in 76.35s (1245 files/s)
[transpile] emitted 814 rules into rules-sources/openvas-port/_transpiled
[transpile] skip reasons (top 10):
           local_security_check             = 60222
           no_eligible_shape                = 33523
           metadata_extract_failed          = 463
           uses_unmodeled_helpers           = 59
           metadata_incomplete              = 5
```

The 60k LSC and 33k no-eligible-shape skips are **honest rejections** —
those VTs require capabilities corvex-rust doesn't have (auth host
scan, runtime payload synthesis, stateful KB). To grow beyond ~830-1000
rules requires either hand-authoring against vendor advisories or
implementing a new runtime capability (Phase C/D).

---

## 6. Rule file format

Every file under `rules-sources/openvas-port/` (transpiled or hand-authored)
follows the same JSON schema:

```jsonc
{
  "id": "openvas-1.3.6.1.4.1.25623.1.0.123456",  // OID-derived for transpiled,
                                                  // corvex-net.<slug> for hand
  "name": "Aardvark Topsites <= 4.2.2 RFI",
  "description": null,
  "severity": "high",                             // critical|high|medium|low|info
  "confidence": "high",                           // optional
  "category": "info-disclosure",
  "owasp_2025": "A05",                            // optional
  "cwe": 73,                                      // optional
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2006-2149"
  ],
  "match_spec": {                                 // pre-built for the runtime engine
    "steps": [
      { "id": "r0", "method": "GET", "uri": "/index.php",
        "headers": [], "body": null, "payload": null },
      { "id": "r1", "method": "GET", "uri": "/sources/join.php?",
        "headers": [], "body": null, "payload": null }
    ],
    "when": [
      { "matcher": { "kind": "status", "step": "r0", "regex": "^2\\d\\d$" } },
      { "matcher": { "kind": "body",   "step": "r0", "regex": "Powered By <a href[^>]+>Aardvark Topsites PHP<" } },
      { "matcher": { "kind": "status", "step": "r1", "regex": "^2\\d\\d$" } },
      { "matcher": { "kind": "body",   "step": "r1", "regex": "Warning.+main\\(" } }
    ]
  },
  "provenance": {
    "openvas_oid": "1.3.6.1.4.1.25623.1.0.200005",
    "transpiled": true,                           // set by harvester; absent for hand-authored
    "cve": ["CVE-2006-2149"],
    "default_ports": [80],
    "openvas_family": "Web application abuses",
    "advisory_urls": [
      "https://nvd.nist.gov/vuln/detail/CVE-2006-2149"
    ]
  },
  "_TRANSPILED": "Auto-emitted by corvex-feed-harvest. Regenerate via `transpile --force`. Hand-author when promoted out of _transpiled/."
}
```

Lowering happens at builder time:
[crates/corvex-rules-builder/src/lower.rs:46](crates/corvex-rules-builder/src/lower.rs#L46)
deserialises `match_spec` directly into a runtime-typed `MatchSpec` —
since the transpiler already produces the canonical AST, no per-source
DSL conversion is needed.

---

## 7. Builder ingestion

`corvex-rules-builder` wires the openvas-port source alongside the
existing three:

```rust
// crates/corvex-rules-builder/src/main.rs
if want(SourceTool::OpenvasPort) {
    let net_dir = cli.sources.join("openvas-port");
    if net_dir.exists() {
        let (rules, stats) = parsers::openvas_port::parse_dir(&net_dir)?;
        all_rules.extend(rules);
        build_report.record(SourceTool::OpenvasPort, stats);
    }
}
```

The parser walks `rules-sources/openvas-port/**/*.json` recursively,
**skipping `_scaffolds/` at any depth**. It deserialises the JSON into
the same `NormalizedRule` type the other parsers emit, then the writer
upserts each row into `rules.sqlite` keyed by `(source_tool='openvas-port',
source_rule_id=<id>)`.

---

## 8. UI integration

The `source_tool='openvas-port'` value is stored as-is in the database
for audit/provenance, but the desktop UI labels it **"Network"** in
user-facing copy. The mapping lives in
[DatabasesView.tsx](crates/corvex-desktop/ui/src/components/DatabasesView.tsx)
via the `sourceLabel()` helper:

```tsx
function sourceLabel(sourceTool: string): string {
  switch (sourceTool) {
    case "openvas-port": return "Network";
    case "nikto":        return "Nikto";
    // …
  }
}
```

Help is in
[HelpView.tsx](crates/corvex-desktop/ui/src/components/HelpView.tsx) under
the "Network rules (hand-authored)" subsection of "Unified rules
catalog", with the bulk-scaffold + transpile workflow embedded as a
runnable code block.

---

## 9. Embedding into the desktop binary

`corvex-desktop/build.rs` reads `program/rules/rules.sqlite` and stamps
its absolute path into `CORVEX_RULES_SQLITE_PATH`. The runtime
`include_bytes!(env!("CORVEX_RULES_SQLITE_PATH"))` embeds the entire DB
into the compiled binary:

[crates/corvex-desktop/src/rules_embed.rs:19](crates/corvex-desktop/src/rules_embed.rs#L19)

```rust
pub const EMBEDDED_RULES_SQLITE: &[u8] =
    include_bytes!(env!("CORVEX_RULES_SQLITE_PATH"));
```

`cargo:rerun-if-changed=program/rules/rules.sqlite` is set so any rebuild
of the catalog automatically invalidates and re-embeds.

**Runtime lookup order** (first hit wins):

1. `<cwd>/rules.sqlite` — power-user override.
2. `<exe-dir>/rules.sqlite` — sibling-of-binary install layout.
3. `<app_data_dir>/dev.fazminnizam.corvex-rust/rules.sqlite` — extracted
   copy of the embedded blob, written on first launch when length /
   first-4KB of the on-disk copy don't match the embedded bytes (catches
   "user upgraded the binary" automatically).
4. None — falls back to legacy embedded test database.

---

## 10. Operational workflow

End-to-end recipe to refresh the openvas-port corpus:

```powershell
# 1. Pull the feed (resumable; ~5 minutes on a fast connection)
cargo run -p corvex-feed-harvest -- sync

# 2. Bulk-transpile (~70 seconds across 12 cores)
cargo run -p corvex-feed-harvest -- transpile

# 3. (Optional) Lint hand-authored rules for clean-room compliance
cargo run -p corvex-feed-harvest -- lint

# 4. Rebuild rules.sqlite — picks up Nikto/ZAP/Burp/openvas-port together
cargo run -p corvex-rules-builder

# 5. Verify in the desktop
cargo tauri dev
#    → Open "Databases" sidebar → "Web signatures" tab
#    → Confirm Network row in per-source coverage table
```

If a previous launch extracted a stale rules.sqlite under
`%APPDATA%\dev.fazminnizam.corvex-rust\rules.sqlite`, the size mismatch
will trigger automatic re-extraction. Force it manually:

```powershell
Remove-Item "$env:APPDATA\dev.fazminnizam.corvex-rust\rules.sqlite" -ErrorAction SilentlyContinue
```

---

## 11. Tests

Unit tests live alongside `transpile.rs`. Run:

```
cargo test -p corvex-feed-harvest --release
```

Coverage:

| Test | What it asserts |
|---|---|
| `pulls_oid_name_family_cves` | NASL metadata extractor pulls each documented field. |
| `transpiles_simple_web_banner_check` | Single-step Web Servers + egrep emits a 1-step rule. |
| `transpiles_cgi_app_banner` | "Web application abuses" + literal CGI path emits. |
| `transpiles_http_header_banner` | `Server:` regex strips the header anchor and emits a `Header` matcher. |
| `transpiles_tls_protocol_name` | TLSv1.0 detector emits a `tls` step + `tls_version` matcher. |
| `transpiles_multistep_two_get` | 2 distinct literal `http_get` paths emit a 2-step rule with per-step matchers. |
| `transpiles_product_detection_fingerprint` | Product detection family + `register_product` emits an info-severity rule. |
| `rejects_dynamic_url_construction` | `string()`-built URLs are rejected (not transpiled wrongly). |
| `rejects_multistep_with_duplicate_path` | Same path twice = retry, not multi-step. |
| `severity_promoted_when_cve_present` | ACT_GATHER_INFO + CVE → medium (not info). |
| `resolves_var_indirection` | `URL = string(dir, "/path"); http_get(item:URL)` resolves to `/path`. |

11 tests, all green.

---

## 12. Rule-count history

Each row reflects a complete `cargo run -p corvex-rules-builder` after
that step's transpiler change.

| Step | openvas-port count | Driver |
|---|---:|---|
| Phase A scaffolding | 1 | Pipeline plumbing only |
| Hand-authored seeds | 6 | 5 web rules from public vendor docs |
| Harvester real | 17 | More hand-authored rules |
| Transpiler v1 (5 shapes) | 129 | First pass with single-shape recognisers |
| + multi-step + `><` substring | 313 | NASL substring operator + status-only steps |
| + dependency chain + var indirect | 392 | KB-routed VTs (fingerprint→vuln pairs) |
| **+ Product detection + `+` concat** | **831** | Standalone fingerprint VTs + NASL `+` operator |

---

## 13. What's deferred

| Capability | Status | Unlocks |
|---|---|---|
| Phase C runtime (TLS handshake, TCP banner) | Schema only — engine fail-closes on non-Http kinds | TLS/banner rules currently ingest but don't fire |
| Phase D runtime (SSH/SMB/SNMP probes + creds) | Schema only — no probe executors | ~60k LSC VTs (Debian/Ubuntu/Fedora/RHSA/etc.) |
| Multi-step recogniser with payload-substitution | Not implemented | ~5,000 web exploit-confirmation VTs |
| Stateful KB / fingerprint→vuln chain at runtime | Replaced by transpiler's static synthesis | Already covered for VTs whose fingerprint VT is also literal |

The transpiler has now tapped the four dominant OpenVAS detection
idioms (direct literal, dir-iterator `string()`, NASL `+` concat,
dependency-chain). The remaining 33k `no_eligible_shape` rejections are
mostly genuine — they require runtime capabilities corvex-rust would
need to add as separate initiatives, not transpiler refinements.

---

## 14. File map

**Implementation:**

- [crates/corvex-feed-harvest/src/main.rs](crates/corvex-feed-harvest/src/main.rs) — CLI surface
- [crates/corvex-feed-harvest/src/sync.rs](crates/corvex-feed-harvest/src/sync.rs) — rsync wrapper + Docker fallback
- [crates/corvex-feed-harvest/src/nasl.rs](crates/corvex-feed-harvest/src/nasl.rs) — NASL metadata extractor
- [crates/corvex-feed-harvest/src/transpile.rs](crates/corvex-feed-harvest/src/transpile.rs) — eligibility recognisers + emitter
- [crates/corvex-feed-harvest/src/scaffold.rs](crates/corvex-feed-harvest/src/scaffold.rs) — hand-authoring stub generator
- [crates/corvex-feed-harvest/src/lint.rs](crates/corvex-feed-harvest/src/lint.rs) — clean-room enforcement
- [crates/corvex-feed-harvest/LICENSE_NOTES.md](crates/corvex-feed-harvest/LICENSE_NOTES.md) — policy
- [crates/corvex-rules-builder/src/parsers/openvas_port.rs](crates/corvex-rules-builder/src/parsers/openvas_port.rs) — JSON parser
- [crates/corvex-rules-builder/src/lower.rs](crates/corvex-rules-builder/src/lower.rs) — `match_spec` deserialisation
- [crates/corvex-rules-builder/src/normalized.rs](crates/corvex-rules-builder/src/normalized.rs) — `SourceTool::OpenvasPort` variant

**Schema:**

- [crates/corvex-rules/src/matcher/spec.rs](crates/corvex-rules/src/matcher/spec.rs) — `StepKind`, new `Matcher` variants

**Vendored corpus:**

- [rules-sources/openvas-port/README.md](rules-sources/openvas-port/README.md) — author guide
- [rules-sources/openvas-port/_transpiled/](rules-sources/openvas-port/_transpiled/) — auto-emitted (regenerable)
- [rules-sources/openvas-port/service/](rules-sources/openvas-port/service/) — hand-authored, service exposure
- [rules-sources/openvas-port/cms/](rules-sources/openvas-port/cms/) — hand-authored, CMS detections
- [rules-sources/openvas-port/appserver/](rules-sources/openvas-port/appserver/) — hand-authored, appserver checks
- [rules-sources/openvas-port/http-misc/](rules-sources/openvas-port/http-misc/) — hand-authored, web misconfig
- [rules-sources/openvas-port/network/](rules-sources/openvas-port/network/) — hand-authored, TLS / banner / Phase C-D placeholders
- [rules-sources/openvas-port/_scaffolds/](rules-sources/openvas-port/_scaffolds/) — dev-only stubs (NEVER ingested)

**Cache (gitignored):**

- `program/feed-cache/openvas/` — the local mirror of the Greenbone Community Feed

**Output:**

- `program/rules/rules.sqlite` — the unified catalog
- `rules-sources/openvas-port/_transpiled/<family>/<oid>.json` — transpiler output

---

## 15. Quick reference

```powershell
# Refresh corpus end-to-end
cargo run -p corvex-feed-harvest -- sync
cargo run -p corvex-feed-harvest -- transpile
cargo run -p corvex-rules-builder

# Inspect the catalog
cargo run -p corvex-rules-builder -- --report program/rules/rules.sqlite

# Hand-author a rule from a feed VT
cargo run -p corvex-feed-harvest -- scaffold --oid 1.3.6.1.4.1.25623.1.0.<N>
# (edit rules-sources/openvas-port/_scaffolds/<oid>.json,
#  promote to a family folder when match_spec is filled in)

# Lint hand-authored rules for accidental NASL copy-paste
cargo run -p corvex-feed-harvest -- lint

# Wipe transpiled output and regenerate
Remove-Item -Recurse -Force rules-sources/openvas-port/_transpiled
cargo run -p corvex-feed-harvest -- transpile --force

# Wipe the desktop's extracted catalog (forces re-extract on next launch)
Remove-Item "$env:APPDATA\dev.fazminnizam.corvex-rust\rules.sqlite" -ErrorAction SilentlyContinue
```
