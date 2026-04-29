# Scanner Rule Unification to a Single SQLite Catalog

> Status: **Phase 1 + Phase 2a + 2b + 2c + 2d (cutover plumbing) complete.**
> The runtime now lets the user flip between the legacy bincode path
> (`--legacy-only`), side-by-side (default), and the unified-rules path
> (`--rules-only`). The final delete of `TestsPlugin` is gated on a
> sustained side-by-side run with no finding deltas.
>
> Last updated: 2026-04-29.

This document is the canonical reference for how `corvex/nikto-rust`
consolidates web vulnerability rules from **OWASP ZAP**, **Burp Suite**, and
**Nikto** into a single SQLite catalog (`rules.sqlite`), and how the runtime
scanner consumes that catalog through a multi-step match engine.

It explains what was built, why each piece exists, what's deferred, and how
to extend the system in subsequent phases.

---

## 1. Motivation

The legacy scanner ships ~7,200 web checks driven from a single source: the
Nikto-format flat-file [program/databases/db_tests](program/databases/db_tests).
That database is parsed at build time, serialised as a `bincode` blob into
`OUT_DIR/databases.bin`, embedded into the binary, and consumed at runtime
by [crates/corvex-plugins/src/tests_plugin.rs](crates/corvex-plugins/src/tests_plugin.rs)
through the Nikto-style DSL (`CODE:200&&BODY:foo` etc.).

The goal of unification is to:

1. **Widen detection coverage** by reusing community-maintained rules from
   OWASP ZAP and PortSwigger BChecks alongside Nikto.
2. Replace the embedded bincode blob with a queryable SQLite catalog
   (filterable by severity, source, OWASP, CWE, category) shippable
   alongside the binary.
3. Keep the existing scanner working **untouched** during the rollout so any
   regression can be diagnosed against a known-good baseline.

---

## 2. Architecture overview

```
┌────────────────────────────── Build time ─────────────────────────────┐
│                                                                        │
│   rules-sources/             ┌──────────────────────────┐  rules.sqlite│
│   ├─ nikto/db_tests          │  corvex-rules-builder    │  ┌─────────┐ │
│   ├─ zap/*.json     ───────► │  parsers + lowering pass │ ─┤rules    │ │
│   └─ burp/*.bcheck           │  + writer (single tx)    │  │rules_meta│ │
│                              └──────────────────────────┘  └─────────┘ │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   │  (sibling to binary, opened read-only)
                                   ▼
┌─────────────────────────────── Runtime ───────────────────────────────┐
│                                                                        │
│   ScanCtx { rule_store: Option<Arc<dyn RuleProvider>>, ... }           │
│                          │                                             │
│      ┌───────────────────┴────────────────────┐                        │
│      ▼                                        ▼                        │
│   TestsPlugin (legacy)                    RulesPlugin (new)            │
│   reads bincode db_tests                  reads RuleProvider           │
│   → Nikto DSL eval                        → MatchSpec multi-step       │
│                                             engine                     │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Crate layout

| Crate | Role |
|-------|------|
| **`corvex-core`** | Foundational types. Hosts only the `RuleProvider` trait + `ExecutableRule` struct (with opaque `serde_json::Value` for `match_spec`). **Does not** depend on `corvex-rules`. |
| **`corvex-rules`** | Read-only access to `rules.sqlite` and the `MatchSpec` AST + multi-step engine. Owns the heavy serde-derived types so they don't bloat downstream compile times. Implements `RuleProvider` on `RuleStore`. |
| **`corvex-rules-builder`** | Standalone CLI binary. Reads vendored sources, parses them, normalises into a common schema, lowers detection logic into `MatchSpec`, persists to SQLite. Mirrors the pattern of `vulndb-builder`. |
| **`corvex-plugins`** | Hosts the new `RulesPlugin` (weight 98) alongside the legacy `TestsPlugin` (weight 99). |
| **`corvex` / `corvex-desktop`** | CLI and Tauri front-end. Look up `rules.sqlite` from the working dir or exe dir at startup, hand a `Arc<RuleStore>` into `ScanCtx`. |

Why this split: a recursive serde-derived `Cond` enum monomorphises against
`serde_json::Serializer<&mut Vec<u8>>` deeply enough to overflow the Windows
MSVC default 1 MB rustc thread stack. Concentrating that cost in the leaf
crate (`corvex-rules`) means everything else compiles fast.

---

## 3. SQLite schema

`rules.sqlite` carries two tables:

### 3.1 `rules`

```sql
CREATE TABLE rules (
    rule_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_tool      TEXT    NOT NULL,    -- 'nikto' | 'zap' | 'burp'
    source_rule_id   TEXT    NOT NULL,    -- e.g. nikto '000001', zap '40012'
    name             TEXT    NOT NULL,
    description      TEXT,
    severity         TEXT    NOT NULL,    -- 'critical'|'high'|'medium'|'low'|'info'
    confidence       TEXT,                -- 'high'|'medium'|'low' | NULL
    category         TEXT,                -- 'sqli'|'xss'|'lfi'|'misconfig'|...
    owasp_2025       TEXT,                -- 'A01'..'A10' if mappable
    cwe              INTEGER,
    refs_json        TEXT NOT NULL DEFAULT '[]',   -- JSON array of refs
    http_method      TEXT,
    uri_template     TEXT,                -- may contain @VAR Nikto-style tokens
    request_body     TEXT,
    request_headers  TEXT,                -- newline-separated
    payloads_json    TEXT NOT NULL DEFAULT '[]',
    detection_json   TEXT NOT NULL,       -- per-source raw detection blob
                                          -- (preserved for Phase 2b/2c
                                          -- richer interpretation)
    source_meta_json TEXT NOT NULL DEFAULT '{}',
    match_spec_json  TEXT,                -- v2: lowered runtime spec; NULL
                                          -- when not yet lowered
    enabled          INTEGER NOT NULL DEFAULT 1,
    UNIQUE (source_tool, source_rule_id)
);

CREATE INDEX idx_rules_severity   ON rules(severity);
CREATE INDEX idx_rules_owasp      ON rules(owasp_2025);
CREATE INDEX idx_rules_source     ON rules(source_tool);
CREATE INDEX idx_rules_category   ON rules(category);
CREATE INDEX idx_rules_executable ON rules(source_tool)
    WHERE match_spec_json IS NOT NULL AND enabled = 1;
```

Schema versioning lives in `crates/corvex-rules-builder/src/schema.rs`:

```rust
pub const SCHEMA_VERSION: u32 = 2;   // v1 = original; v2 = adds match_spec_json
```

Migrations follow the existing project pattern (probe `pragma_table_info`,
`ALTER TABLE ADD COLUMN` if missing) — see
[crates/corvex-core/src/vulndb/schema.rs](crates/corvex-core/src/vulndb/schema.rs).

### 3.2 `rules_meta`

```sql
CREATE TABLE rules_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

Carries provenance and per-source counters:

| Key | Value |
|-----|-------|
| `schema_version` | `2` |
| `build_ts` | ISO-8601 timestamp |
| `nikto_commit` / `zap_commit` / `burp_commit` | upstream commit SHAs |
| `ingested_count_<source>` | rules that survived parsing |
| `skipped_count_<source>` | rules dropped by parser |
| `skip_reasons_<source>_json` | per-reason breakdown |
| `lowered_count_<source>` | rules with non-NULL `match_spec_json` |
| `unlowered_reasons_<source>_json` | why each un-lowered rule was skipped |

---

## 4. Vendored sources

All upstream rule data lives under [rules-sources/](rules-sources/):

```
rules-sources/
├── VENDOR.md                # commits, licenses, attribution
├── nikto/
│   └── db_tests             # canonical copy of program/databases/db_tests
├── zap/
│   ├── COMMIT               # zap-extensions upstream commit SHA
│   └── *.json               # extracted rule descriptors (one per rule)
└── burp/
    ├── COMMIT               # PortSwigger/BChecks upstream commit SHA
    └── **/*.bcheck          # raw BCheck DSL files (subdirs preserved)
```

### 4.1 Nikto

Verbatim copy of the in-repo `program/databases/db_tests`. The builder reads
this canonical location so the CSV format is independent of any future
restructuring of the legacy Perl-style layout.

### 4.2 ZAP

ZAP active and passive scan rules are written in **Java**, so executable
logic doesn't port directly. Instead, an extractor walks the upstream
`zaproxy/zap-extensions` Java sources (`*ScanRule*.java`) and pulls portable
**metadata** — id, name, description, risk code, confidence code, CWE id,
WASC id, references, alert tags, and any statically-declared payload arrays
— into one JSON file per rule.

The extractor is `extract_zap.py` in the temporary clone tree at vendor
time; only the resulting JSON descriptors are committed under
`rules-sources/zap/`. See `VENDOR.md` for the procedure to refresh.

Today's vendor produces **51 ZAP rule descriptors** from
`zap-extensions@2ffee47f`.

### 4.3 Burp

PortSwigger's BChecks repository ships the rules as `.bcheck` files in their
own declarative DSL. We vendor the raw files verbatim (subdirectory
hierarchy preserved). Today's vendor is **263 BCheck files** from
`BChecks@97810d82`.

---

## 5. Builder pipeline

`crates/corvex-rules-builder/` is a standalone CLI binary that:

1. **Walks the three vendored source trees**, dispatching each file to the
   matching parser module.
2. **Normalises** every parsed rule into `NormalizedRule` (a flat struct
   shared across sources — see `src/normalized.rs`).
3. **Lowers** detection logic into `MatchSpec` where possible (Phase 2a:
   Nikto only).
4. **Inserts** every rule inside a single transaction; existing rows with
   matching `(source_tool, source_rule_id)` are upserted.
5. **Reports** ingestion + lowering stats per source.

### 5.1 Parser modules

#### `parsers::nikto`

Reuses the CSV reader configuration from [crates/corvex-core/build.rs](crates/corvex-core/build.rs) (the same one that
feeds the legacy bincode pipeline). For each `TestRow`:

- `id`, `references`, `tuning`, `uri`, `method`, `dsl`, `message`, `data`,
  `headers` are mapped to columns.
- Severity is derived from `tuning` chars via the same table used by the
  existing `tests_plugin::severity_from_tuning`.
- A coarse `category` is picked from the highest-priority tuning char
  (`8 → rce`, `9 → sqli`, `4 → xss`, etc.).
- Best-effort `owasp_2025` mapping based on category.
- `detection_json = {"kind": "nikto_dsl", "raw": "<dsl>", "tuning": "<chars>"}`.

Expected: ~7,236 rules, near-100% ingestion success.

#### `parsers::zap`

Walks `*.json` files under `rules-sources/zap/`. Per-rule fields:

- `riskcode` (0..3) → severity (`info`/`low`/`medium`/`high`).
- `confidence` (0..4) → confidence (`low`/`medium`/`high`).
- `alert_tags` keys like `OWASP_2021_A03_INJECTION` → `owasp_2025 = "A03"`.
- Coarse `category` inferred from class name and rule name.
- `detection_json = {"kind": "zap_metadata", "payloads": [...], "patterns": [...], "raw_class": "...", "passive": <bool>}`.

#### `parsers::burp`

Walks `**/*.bcheck` files. Each file has:

- Optional `#`-comment header lines (skipped).
- A `metadata:` block (key/value pairs).
- A body with `given/if/then` directives in BCheck DSL.

We extract metadata into normalised columns; the body is preserved verbatim
in `detection_json = {"kind": "bcheck", "language": "v2-beta", "body": "<raw>", "tags": [...]}`.

### 5.2 Severity normalisation

`crates/corvex-rules-builder/src/severity.rs` is the single source of truth
for mapping per-source severity values to the unified scale:

| Source | Input | Output |
|--------|-------|--------|
| Nikto | tuning chars | reuses `severity_from_tuning` (mirrors `crates/corvex-plugins/src/tests_plugin.rs:31-49`) |
| ZAP | `riskcode` 0/1/2/3 | `info`/`low`/`medium`/`high` |
| ZAP | `confidence` 0..4 | `low`/`medium`/`high` (4 → `high`) |
| Burp | `severity` literal | direct |
| Burp | `confidence` literal (`tentative`/`firm`/`certain`) | `low`/`medium`/`high` |

### 5.3 Lowering: detection_json → match_spec_json

`crates/corvex-rules-builder/src/lower.rs` produces a `MatchSpec` from the
raw detection blob:

- **Nikto** (`kind = "nikto_dsl"`): parse with `corvex_core::dsl::parse`,
  then map each `(Matcher, negated)` pair into a `LeafCond { matcher, negate }`.
  Single step (`r0`) carrying the URI / method / body / headers. Phase 2a
  ships this; **94.1% of Nikto rules lower successfully**. The remaining
  ~6% have empty URI templates or malformed DSL — `TestsPlugin` would skip
  them too.

- **ZAP** (`kind = "zap_metadata"`): **deferred to Phase 2b**. The raw
  payload arrays + pattern strings are preserved in `detection_json` for
  later interpretation.

- **Burp** (`kind = "bcheck"`): **deferred to Phase 2c**. The BCheck DSL
  body is preserved verbatim in `detection_json`.

Un-lowered rules get `match_spec_json = NULL`. The `idx_rules_executable`
partial index lets the runtime efficiently filter to executable rows only.

### 5.4 CLI surface

```
corvex-rules-builder --sources rules-sources --output rules.sqlite
corvex-rules-builder --sources rules-sources --output rules.sqlite --filter-source zap
corvex-rules-builder --report rules.sqlite
```

The build prints per-source ingest counts, MatchSpec coverage, severity
distribution, OWASP coverage, JSON-validity check, and full `rules_meta`.

---

## 6. The `MatchSpec` AST (Phase 2a shape)

Lives in [crates/corvex-rules/src/matcher/spec.rs](crates/corvex-rules/src/matcher/spec.rs).
Phase 2a uses a **flat non-recursive** shape sized to what Nikto needs:

```rust
pub struct MatchSpec {
    pub steps: Vec<StepSpec>,
    /// Conditions are AND-joined. Phase 2b/2c will swap this for a richer
    /// recursive Cond tree (with hand-written serde, not derive).
    pub when: Vec<LeafCond>,
}

pub struct StepSpec {
    pub id: StepId,
    pub method: String,
    pub uri: String,                  // may contain @VAR + {{bind}} tokens
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub payload: Option<Payload>,
    pub readonly_cookies: bool,
}

pub struct LeafCond {
    pub matcher: Matcher,
    pub negate: bool,
}

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Matcher {
    Status   { step: StepId, regex: String },
    Body     { step: StepId, regex: String },
    Header   { step: StepId, name: String, regex: String },
    Cookie   { step: StepId, name: String, regex: String },
}

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    RandomToken { len: usize, alphabet: Alphabet, bind: String },
    Fixed       { value: String, bind: String },
    FromList    { values: Vec<String>, bind: String },
}
```

This is sufficient for the Nikto-lowered subset and exactly mirrors the
power of today's DSL (`CODE:.. && BODY:.. && HEADER:.. [ && !COOKIE:.. ]`).

### 6.1 Why not recursive in Phase 2a

A recursive `Cond` enum (`All(Vec<Cond>)`, `Any(Vec<Cond>)`, `Not(Box<Cond>)`,
plus the cross-step deltas, reflection, and OOB variants) was attempted
first. It compiled on Linux but on Windows MSVC:

- `recursion_limit` had to jump from the default 128 to 4096 to typecheck.
- Even at 4096, `serde_json::Serializer<&mut Vec<u8>>` monomorphisation
  through the recursive `Cond` overflowed the default 1 MB rustc thread
  stack (`STATUS_STACK_OVERFLOW` exit `0xc00000fd`).
- Bumping `RUST_MIN_STACK` to 16 MB via `.cargo/config.toml` lifted the
  hard overflow but compile time grew unbounded — observed ≥60 minutes on
  the single crate without producing an `rmeta`.

**Decision:** ship the flat shape now (sufficient for Nikto), bring the
recursive `Cond` back in Phase 2b with a **hand-written `Serialize` /
`Deserialize` impl** so the macro doesn't expand the nested generics. This
keeps `corvex-rules` compiling in seconds even after the richer variants
land.

The `.cargo/config.toml` `RUST_MIN_STACK = 16777216` setting is kept as a
safety net for the eventual richer types.

---

## 7. Multi-step engine

[crates/corvex-rules/src/matcher/engine.rs](crates/corvex-rules/src/matcher/engine.rs) implements:

```rust
pub async fn run_match(
    spec: &MatchSpec,
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
) -> Result<Option<MatchHit>>;

pub fn eval_when(
    leaves: &[LeafCond],
    steps: &[StepResult],
    jar: &CookieJar,
) -> std::result::Result<bool, EvalError>;

pub fn parse_json(raw: &str) -> Result<MatchSpec, serde_json::Error>;
pub fn to_json(spec: &MatchSpec) -> Result<String, serde_json::Error>;
```

`run_match` integrates with the existing scanner pipeline:

1. **Validate step refs.** Every leaf condition's `step_id` must point at a
   `StepSpec` in `spec.steps` (otherwise the rule is dropped with a warn
   log; mirrors how `TestsPlugin` skips rules whose DSL fails to parse).
2. **Materialise payload bindings.** For each step's `Payload`, generate
   the bound value once before any HTTP traffic:
   - `Fixed` → bind to literal value.
   - `RandomToken { len, alphabet }` → generate via `rand::thread_rng`.
   - `FromList { values }` → take the first value (Phase 2b will fan out).
3. **Per step, sequentially:**
   - Expand `@VAR` tokens via `corvex_core::vars::expand_all` (shared with
     `TestsPlugin`).
   - Apply the scan-level evasion filter via `ctx.evasion.apply`.
   - Interpolate `{{bind}}` slots **after** evasion (so an evasion rule
     can't mangle a payload token).
   - Build a `Request` with the same shape `TestsPlugin` produces.
   - Call `ctx.nfetch(mark, &mut req)` — same prefetch / cookie / postfetch
     pipeline as legacy.
4. **Evaluate** `spec.when` against the collected `StepResult`s:
   - Each `LeafCond` runs its regex against the named step's response
     (`Status`, `Body`, `Header`) or the cookie jar (`Cookie`).
   - `negate = true` flips the verdict.
   - All leaves AND-join.
5. **Return** `Some(MatchHit)` on truth, `None` otherwise. Per-rule errors
   are non-fatal — the caller logs and continues, matching `TestsPlugin`'s
   pattern.

### 7.1 Future-proofing for Phase 2b/2c

The engine signature is already shaped for multi-step: `Vec<StepResult>` is
indexed by `StepId`, not position. When the recursive `Cond` tree lands,
`eval_when` becomes `eval_cond` taking a `Cond` recursively, but the runner
shape (`run_match`) and step pipeline don't change.

The richer variants planned for 2b/2c:

- `Cond::All` / `Any` / `Not` — logical algebra over leaves.
- `Cond::StatusDelta { a, b, op, value }` — diff response codes between two
  steps (error-based SQLi).
- `Cond::BodyLenDeltaPct { a, b, op, value }` — body-size delta
  (boolean-blind).
- `Cond::ElapsedDeltaMs { a, b, op, value }` — time-based blind. Will need
  a per-host serialisation guard so concurrency + rate-limiting don't
  produce false positives.
- `Cond::HeaderDiff { a, b, name, mode }` — presence/value diff.
- `Cond::Reflects { from, in_step, location, encoding }` — payload
  reflection, decoupled from where the payload was injected.
- `Cond::OobInteraction { token, channel }` — placeholder for an
  Interactsh-style collaborator (not wired in 2a/2b/2c; deferred).

---

## 8. Runtime integration

### 8.1 `RuleProvider` trait

Lives in `corvex-core` so `ScanCtx` can hold the rule source without a
dependency on `corvex-rules`:

```rust
// crates/corvex-core/src/matcher/provider.rs
pub struct ExecutableRule {
    pub rule_id: i64,
    pub source_tool: String,
    pub source_rule_id: String,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub category: Option<String>,
    pub owasp_2025: Option<String>,
    pub cwe: Option<i64>,
    pub references: Vec<String>,
    /// Opaque MatchSpec JSON. Deserialise with
    /// `corvex_rules::matcher::parse_json` at the use site.
    pub match_spec: serde_json::Value,
}

pub trait RuleProvider: Send + Sync {
    fn iter_executable(&self, sources: &[&str]) -> Vec<ExecutableRule>;
    fn count_by_source(&self) -> Vec<(String, u64)>;
}
```

`corvex_rules::RuleStore` implements `RuleProvider`. The `match_spec` field
is a `serde_json::Value` rather than a typed `MatchSpec` — the consumer
plugin parses lazily via `corvex_rules::matcher::parse_json`. This isolates
the heavy serde generics to one consumer.

### 8.2 `ScanCtx::rule_store`

```rust
pub struct ScanCtx {
    // ... existing fields ...
    pub vulndb: Option<Arc<VulnDb>>,
    pub rule_store: Option<Arc<dyn crate::matcher::RuleProvider>>,
}
```

Both binary entry points construct it the same way:

```rust
let rule_store: Option<Arc<dyn corvex_core::matcher::RuleProvider>> = {
    let candidates = [
        std::env::current_dir().ok().map(|p| p.join("rules.sqlite")),
        std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join("rules.sqlite"))),
    ];
    let path = candidates.into_iter().flatten().find(|p| p.exists());
    match path {
        Some(p) => match corvex_rules::RuleStore::open(&p) {
            Ok(store) => Some(Arc::new(store) as _),
            Err(_) => None,
        },
        None => None,
    }
};
```

When `rules.sqlite` is absent the binary keeps working with the legacy
`TestsPlugin`-only path — important for the side-by-side rollout.

### 8.3 `RulesPlugin`

[crates/corvex-plugins/src/rules_plugin.rs](crates/corvex-plugins/src/rules_plugin.rs):

```rust
static INFO: PluginInfo = PluginInfo {
    name: "rules",
    full_name: "Corvex Unified Rules",
    description: "Run the unified rules.sqlite catalog (ZAP + Burp; Nikto stays on TestsPlugin during parity).",
    weight: 98,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};
```

`on_scan` flow:

1. If `ctx.rule_store` is `None`, return early.
2. `iter_executable(&["zap", "burp"])` — Phase 2a filters out `nikto`
   rows so `TestsPlugin` keeps owning the legacy path. **No duplicate
   findings during parity.**
3. For each rule: deserialise `match_spec` JSON via
   `corvex_rules::matcher::parse_json`, run `matcher::run_match`, emit a
   `ReportItem` on hit.
4. Severity flows through verbatim from the persisted column.

Phase 2a result: Nikto rules light up via `TestsPlugin`, ZAP/Burp rules
defer to Phase 2b/2c. When 2b/2c land, the `["zap", "burp"]` filter expands
or drops entirely.

### 8.4 Plugin registration

[crates/corvex-plugins/src/lib.rs](crates/corvex-plugins/src/lib.rs)
registers `RulesPlugin` at weight 98, just before `TestsPlugin` at weight 99:

```rust
// Unified rules catalog (ZAP+Burp during the Phase-2a parity period).
Arc::new(rules_plugin::RulesPlugin::default()),
// The big one — runs db_tests. Weight 99 = last.
Arc::new(tests_plugin::TestsPlugin::default()),
```

---

## 9. Verification

### 9.1 Parity test

[crates/corvex-rules-builder/tests/parity_nikto.rs](crates/corvex-rules-builder/tests/parity_nikto.rs)
exhaustively cross-checks the new `eval_when` against the legacy
`DslEvaluator::eval` over a fixture grid:

- Status-code matchers (`CODE:200`, `CODE:^4..$`, `!CODE:200`).
- Body matchers (`BODY:phpinfo\(\)`, `!BODY:nope`).
- Header matchers (`HEADER:server:(?i)nginx`).
- Cookie matchers (`COOKIE:PHPSESSID:abc`).
- Negation (`!CODE:404`, `!BODY:foo`, `!HEADER:server:tomcat`).
- AND-conjunction (`CODE:200&&BODY:hello&&HEADER:server:(?i)nginx`).
- A combined grid running 6 DSLs against 4 (status, body, header) shapes.

Run it with:

```
cargo test -p corvex-rules-builder --test parity_nikto
```

Phase 2a status: **5/5 pass.**

### 9.2 Build verification

```
$ cargo run -p corvex-rules-builder -- --report rules.sqlite

[counts by source]
  burp    263
  nikto   7236
  zap     51
  total   7550

[severity by source]
  ...

[MatchSpec executable coverage]
  burp    0   / 263   (0.0%)    # deferred to Phase 2c
  nikto   6812 / 7236 (94.1%)   # Phase 2a target
  zap     0   / 51    (0.0%)    # deferred to Phase 2b

[OWASP-2025 coverage]
  burp    77  / 263   (29.3%)
  nikto   5361/ 7236  (74.1%)
  zap     51  / 51    (100.0%)

[invalid JSON columns] 0  (expected 0)
```

The 424 un-lowered Nikto rules (7236 − 6812) are rules whose URI is empty
or whose DSL fails `corvex_core::dsl::parse` — `TestsPlugin` skips them
identically. Behaviour parity is therefore preserved by construction.

### 9.3 Smoke test

```
$ ./target/debug/corvex --host http://example.invalid --maxtime 5
- Corvex v0.1.0 (Rust)
+ rules.sqlite loaded (.../rules.sqlite): burp=263, nikto=7236, zap=51
+ scan start: 2026-04-28 23:52:23Z
...
```

The CLI auto-discovers `rules.sqlite` from cwd or exe dir, prints
per-source counts, and proceeds. No regression to the existing scan
pipeline.

---

## 10. Compile-time considerations (Windows MSVC)

Two settings are **load-bearing** for the build to complete on Windows:

### 10.1 `.cargo/config.toml` env

```toml
[env]
RUST_MIN_STACK = "16777216"   # 16 MB
```

Equalises rustc's per-thread stack with Linux's default 8 MB (Windows MSVC
defaults to 1 MB). Required for the recursive `Cond` enum that returns in
Phase 2b — without this, serde monomorphisation overflows mid-compile.

### 10.2 Crate-level `recursion_limit` in `corvex-rules`

Reserved (the bump was pulled when the recursion came out of `Cond`, but
the comment in [crates/corvex-rules/src/lib.rs](crates/corvex-rules/src/lib.rs)
explains the future need). When the recursive `Cond` returns:

```rust
#![recursion_limit = "4096"]
```

belongs at the top of `corvex-rules/src/lib.rs` (not at a module level —
`recursion_limit` is a crate attribute).

### 10.3 Compile times observed

| Stage | Pre-refactor | Post-refactor |
|-------|--------------|---------------|
| `corvex-core` (cold) | 60+ min wedged | 13.7 s |
| `corvex-rules` (cold) | hours / stack overflow | 2.4 s |
| `corvex-rules-builder` | n/a | 9 s |
| Whole CLI workspace | hours | 13.6 s |

The refactor's two key moves were (a) hosting the heavy types in
`corvex-rules` rather than `corvex-core`, and (b) flattening the recursive
`Cond` to `Vec<LeafCond>` for Phase 2a.

---

## 11. Phased rollout plan

### Phase 1 (complete)

- Build `corvex-rules-builder` with three parsers.
- Vendor sources under `rules-sources/`.
- Produce `rules.sqlite` with normalised columns.
- Verify per-source ingest succeeds end-to-end.

### Phase 2a (complete — this branch)

- `corvex-rules` reader crate + `MatchSpec` (flat) + multi-step engine.
- `RuleProvider` trait in `corvex-core`.
- Builder lowering pass for Nikto DSL → MatchSpec.
- `RulesPlugin` registered side-by-side with `TestsPlugin`, scoped to
  `source != 'nikto'` so no duplicate findings during parity.
- `ScanCtx.rule_store` wired in CLI + desktop.
- Parity test green (5/5).
- 94.1% Nikto MatchSpec coverage.

### Phase 2b (complete)

- **Improved `extract_zap.py`** to pull every `String[]` array and
  `Pattern.compile("...")` regex from each `*ScanRule.java`, not just
  arrays whose name contains "PAYLOAD" (Phase 1's heuristic). Result: 21
  of 51 ZAP rules (~41%) now expose extractable detection signal — up
  from 1/51 in Phase 1.
- **`lower::lower_zap`** translates the lowerable subset into the same
  flat `MatchSpec` shape Nikto uses:
  - Patterns are filtered by Rust regex compile-success (drops Java
    `\1`-backref / lookaround patterns RE2 rejects).
  - Surviving patterns are joined into one alternation under a single
    `Body` matcher.
  - Rules with payloads bind `{{ZAP}}` into `/?fuzz={{ZAP}}` via
    `Payload::FromList` (capped at 16 values to keep the persisted JSON
    bounded).
  - Rules with patterns-only become passive: GET `/` + body match.
- **17 ZAP rules now have executable `match_spec_json`**
  (33.3% of the vendored 51). Examples:
  - `40008` ParameterTamper — 6 payload values + Tomcat / Microsoft VBScript
    / OLE DB / Java servlet exception alternation regex.
  - `10045` SourceCodeDisclosureWebInf — passive web.xml leak detection.
  - `20017` SourceCodeDisclosureCVE-2012-1823 — passive PHP source leak.
  - `40003` CrlfInjection — payload list + CRLF reflection check.
- The recursive `Cond` enum was *not* needed for Phase 2b after all — the
  flat `Vec<LeafCond>` shape covers passive + simple-active rules cleanly.
  Recursive `Cond` (with hand-written serde) is still queued for Phase
  2b.5 / 2c when cross-step deltas / OR-trees come up in real upstream
  rules we want to lower.
- `RulesPlugin` already targets `["zap", "burp"]`; the 17 lowered ZAP
  rules fire automatically with no plugin code change.
- Parity test still green (5/5) — no regression.

**Phase 2b coverage summary:**

| Source | Ingested | Lowered | Pct |
|--------|----------|---------|-----|
| Nikto  | 7,236    | 6,812   | 94.1% |
| ZAP    | 51       | 17      | 33.3% |
| Burp   | 263      | 0       | 0% (Phase 2c) |
| **Total** | **7,550** | **6,829** | **90.5%** |

**Un-lowered ZAP rules (34/51):** rules whose detection logic depends on
imperative Java code (random tokens generated in-situ, request mutation
via `getNewMsg()` + `setRequestBody()`, etc.) — no extractable signal in
the source. These remain catalogued (severity, OWASP, CWE, references) but
not executable. Phase 2c+ may add rule-by-rule hand-curated lowerings for
high-value entries (XSS, SQLi reflection-based, etc.) once cross-step
`Cond` lands.

### Phase 2c (complete)

- **`lower::lower_burp`** parses three BCheck shapes into the same flat
  `MatchSpec` the other sources use:
  1. **Passive single-pattern.** `given response then if {latest.response}
     matches "REGEX" then report ...` → single GET `/` step + body matcher
     against the regex.
  2. **Active literal-path single-request.** `send request called X:
     path: "/foo" ; if {X.response.body} matches "REGEX"` → GET `/foo` +
     body match. The `in` form (`if "literal" in {X.response.body}`) is
     also handled, with the literal regex-escaped before persisting.
  3. **Active path-list run-for-each.** `run for each: paths = "/a", "/b"`
     followed by `send request called X: path: {paths}` → URI becomes
     `{{burp_path}}` with a `Payload::FromList` binding (capped at 16
     paths). Phase-2a runner takes the first value only; full per-path
     fan-out lands in Phase 2c.5.
- BCheck rules with multi-step `send`s, compound predicates (`and` / `or`
  inside `if`), header/status-code-only checks without an accompanying
  body matcher, or `define:` blocks beyond simple path lists are skipped
  with reason `burp_unsupported_dsl_shape`. They remain catalogued (with
  detection_json preserved) for Phase 2c.5.
- **91 BCheck rules now have executable `match_spec_json`** (34.6% of
  the vendored 263). Examples:
  - `bcheck-leaked-aws-token` — passive scan for `AKIA[0-9A-Z]{16}` in any
    response body.
  - `bcheck-exposed-git-directory` — GET `{{burp_path}}` against
    `[/.git/config, /.git/config~]` with body match `\[core\]`.
  - `bcheck-Cookie-SameSite-Disabled` — passive `(?i)(SameSite=None)`.
  - `bcheck-jsMapFile`, `bcheck-detectRateLimiter`, `bcheck-client_secret`,
    `bcheck-gitlab-ci-discovery`, …
- The recursive `Cond` enum still wasn't needed — none of the lowered
  BChecks required OR/NOT or cross-step deltas. The flat
  `Vec<LeafCond>` shape continues to cover everything Phase 2 has
  shipped. Recursive `Cond` (with hand-written serde) stays queued for
  whenever a high-value rule needs it.
- Parity test (5/5) still green. No regressions.

**End-of-Phase 2c coverage summary:**

| Source | Ingested | Lowered | Pct |
|--------|----------|---------|-----|
| Nikto  | 7,236    | 6,812   | 94.1% |
| ZAP    | 51       | 17      | 33.3% |
| Burp   | 263      | 91      | 34.6% |
| **Total** | **7,550** | **6,920** | **91.7%** |

### Future (post-Phase 2c)

- **Phase 2c.5 / 2d.0 — fan-out + recursion.**
  - Bind-fan-out: `Payload::FromList` runs the step once per value rather
    than just the first. Needed for active fuzzing where each payload is
    its own request.
  - Recursive `Cond` with hand-written serde impls when a real upstream
    rule needs OR / NOT trees or cross-step deltas.
  - Per-host serialisation for time-based rules (`ElapsedDeltaMs` cond)
    so concurrent scans don't false-positive the timing oracle.
  - Header / status-code matchers in BCheck lowering, increasing the
    Burp coverage past the body-only template.

### Phase 2d (cutover plumbing — complete)

- **Two new CLI flags** in [crates/corvex-core/src/cli.rs](crates/corvex-core/src/cli.rs):
  - `--rules-only` — runs the scan via the unified `rules.sqlite` path
    only. `RulesPlugin`'s source filter widens to
    `["nikto", "zap", "burp"]`, and `TestsPlugin` early-returns from
    `on_scan`. Produces findings purely from the new path.
  - `--legacy-only` — inverse: `RulesPlugin` early-returns,
    `TestsPlugin` runs unchanged. Produces findings purely from the
    legacy bincode path. Use this as the parity baseline.
  - Default (no flag) is unchanged — side-by-side with `RulesPlugin`
    handling `["zap", "burp"]` and `TestsPlugin` owning Nikto.
- **Both plugins read `ctx.cli.rules_only` / `ctx.cli.legacy_only`** at
  the top of `on_scan`. No registry or weight changes; the flags toggle
  behaviour at scan time.
- **CLI smoke test passed:** both flags accept cleanly and the rules
  store still loads regardless of which path is selected.

### Phase 2d.5 (cutover validation — next)

- **Parity test extended** to spin up a fixture HTTP server (Docker
  DVWA + WordPress + a handful of misconfig endpoints) and run:
  1. `corvex --legacy-only --host fixture` → record finding set as the
     baseline.
  2. `corvex --rules-only --host fixture` → record finding set as the
     candidate.
  3. Diff `(check_id, uri, message)` tuples; the symmetric difference
     must be empty (or only contain documented un-lowered Nikto rules,
     which the test asserts against the `unlowered_reasons_nikto_json`
     count from the build).
- Once green for one release cycle, **flip the default**: change
  `RulesPlugin`'s default source filter to `["nikto", "zap", "burp"]`
  and make `TestsPlugin` no-op unless `--legacy-only` is set.

### Phase 2e (delete legacy)

- After the default flip has been stable for one release:
  - Delete `crates/corvex-plugins/src/tests_plugin.rs` and its
    registration in `crates/corvex-plugins/src/lib.rs`.
  - Delete the bincode `db_tests` build path in
    `crates/corvex-core/build.rs::load_tests`.
  - Drop the `tests` field from `Databases` in
    `crates/corvex-core/src/db/types.rs` and the lazy load step in
    `crates/corvex-core/src/db/mod.rs`.
  - Drop `--legacy-only` from `Cli` (or keep it as a hidden no-op for
    backwards-compat scripting — judgment call).
  - Other Nikto DBs (`db_outdated`, `db_favicon`, `db_realms`,
    `db_variables`, `db_headers_*`, etc.) stay; they back different
    plugins (`OutdatedPlugin`, `FaviconPlugin`, `AuthPlugin`, etc.) and
    are independent of the unified-rules effort.

### Future (not in current roadmap)

- OOB collaborator service (Interactsh-style) so `Cond::OobInteraction`
  becomes executable.
- Fan-out `Payload::FromList` semantics that emit a finding per value.
- ZAP regex flavour translation (java.util.regex → Rust's RE2 — backref /
  lookaround removal).
- BCheck "v2-beta" full DSL coverage including arbitrary `define:` /
  `run for each:` blocks beyond simple path lists.

---

## 12. Files of interest

### Created

```
crates/corvex-rules/                        # reader + MatchSpec + engine
crates/corvex-rules/Cargo.toml
crates/corvex-rules/src/lib.rs              # RuleStore + RuleProvider impl
crates/corvex-rules/src/matcher/mod.rs
crates/corvex-rules/src/matcher/spec.rs     # MatchSpec, LeafCond, Matcher, Payload
crates/corvex-rules/src/matcher/engine.rs   # run_match, eval_when

crates/corvex-rules-builder/                # builder binary
crates/corvex-rules-builder/Cargo.toml
crates/corvex-rules-builder/src/main.rs
crates/corvex-rules-builder/src/normalized.rs
crates/corvex-rules-builder/src/severity.rs
crates/corvex-rules-builder/src/schema.rs
crates/corvex-rules-builder/src/writer.rs
crates/corvex-rules-builder/src/report.rs
crates/corvex-rules-builder/src/lower.rs    # detection_json -> MatchSpec
crates/corvex-rules-builder/src/parsers/mod.rs
crates/corvex-rules-builder/src/parsers/nikto.rs
crates/corvex-rules-builder/src/parsers/zap.rs
crates/corvex-rules-builder/src/parsers/burp.rs
crates/corvex-rules-builder/tests/parity_nikto.rs

crates/corvex-core/src/matcher/mod.rs
crates/corvex-core/src/matcher/provider.rs  # RuleProvider trait, ExecutableRule

crates/corvex-plugins/src/rules_plugin.rs   # new RulesPlugin

rules-sources/                              # vendored upstream content
rules-sources/VENDOR.md
rules-sources/nikto/db_tests
rules-sources/zap/COMMIT
rules-sources/zap/*.json
rules-sources/burp/COMMIT
rules-sources/burp/**/*.bcheck

.cargo/config.toml                          # RUST_MIN_STACK=16MB
```

### Modified

```
Cargo.toml                                  # workspace members + deps
.gitignore                                  # /rules.sqlite ignored
crates/corvex-core/src/lib.rs               # pub mod matcher
crates/corvex-core/src/scan.rs              # ScanCtx.rule_store
crates/corvex/Cargo.toml                    # depends on corvex-rules
crates/corvex/src/main.rs                   # rule_store loading
crates/corvex-desktop/Cargo.toml            # depends on corvex-rules
crates/corvex-desktop/src/commands.rs       # rule_store loading
crates/corvex-plugins/Cargo.toml            # depends on corvex-rules
crates/corvex-plugins/src/lib.rs            # register RulesPlugin
```

### Untouched

- `crates/corvex-plugins/src/tests_plugin.rs` — the legacy Nikto runner
  keeps working unchanged. The Phase 2d cutover is the only PR that
  touches it.
- `crates/corvex-core/build.rs` — the bincode `databases.bin` pipeline
  remains in place during Phase 2.
- `crates/corvex-core/src/db/types.rs` — `TestRow` and friends are
  unchanged.
- All other `corvex-plugins/*` modules.

---

## 13. Operational notes

### 13.1 Building `rules.sqlite`

```
cargo run -p corvex-rules-builder -- \
    --sources rules-sources \
    --output  rules.sqlite

# Inspect the build report after the fact:
cargo run -p corvex-rules-builder -- --report rules.sqlite

# Filter to a single source while iterating:
cargo run -p corvex-rules-builder -- \
    --sources rules-sources \
    --output  rules-zap-only.sqlite \
    --filter-source zap
```

### 13.2 `rules.sqlite` location at runtime

The CLI and desktop binaries look for `rules.sqlite` in:

1. The current working directory.
2. The directory containing the binary itself.

If neither location holds the file, the binary logs a debug message and
proceeds without it (legacy `TestsPlugin` keeps running). This makes the
file optional for development and easy to swap during testing.

The file is **excluded** from the repo (see `.gitignore`); it is a build
artefact regenerated from `rules-sources/` whenever needed.

### 13.3 Refreshing vendored sources

```
# Burp BChecks:
cd .tmp-vendor && git clone --depth 1 https://github.com/PortSwigger/BChecks.git
python -c "..."  # copy *.bcheck preserving subdirs (handles spaces)
git -C BChecks rev-parse HEAD > rules-sources/burp/COMMIT

# OWASP ZAP (sparse-clone the rule addOns only):
cd .tmp-vendor && git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/zaproxy/zap-extensions.git
git -C zap-extensions sparse-checkout set \
    addOns/ascanrules/src/main/java \
    addOns/ascanrulesAlpha/src/main/java \
    addOns/ascanrulesBeta/src/main/java \
    addOns/pscanrules/src/main/java \
    addOns/pscanrulesAlpha/src/main/java \
    addOns/pscanrulesBeta/src/main/java
python extract_zap.py             # writes rules-sources/zap/*.json
git -C zap-extensions rev-parse HEAD > rules-sources/zap/COMMIT
```

After refreshing, rerun the builder and the parity test. Update the
`MatchSpec executable coverage` numbers in this doc if they materially shift.

### 13.4 Adding a new rule source

1. Create `crates/corvex-rules-builder/src/parsers/<name>.rs` returning
   `(Vec<NormalizedRule>, ParseStats)`.
2. Add a `SourceTool::Foo` variant to
   [crates/corvex-rules-builder/src/normalized.rs](crates/corvex-rules-builder/src/normalized.rs)
   and to [crates/corvex-rules/src/lib.rs](crates/corvex-rules/src/lib.rs).
3. Wire into `crates/corvex-rules-builder/src/main.rs` alongside the
   existing three.
4. Vendor under `rules-sources/<name>/` with a `COMMIT` marker and update
   `rules-sources/VENDOR.md`.
5. Decide whether to lower into `MatchSpec` now or defer; if deferring,
   `lower::try_lower` returns `Ok(None)` for that source.
6. Update `RulesPlugin` if you want the new source to fire in the side-by-
   side period.

---

## 14. Known limitations

- **Phase 2a only fires Nikto rules through the new path (and only does so
  internally — `RulesPlugin` filters out `nikto` until the cutover).** ZAP
  and Burp rules are catalogued but not executed yet.
- **Time-based detection isn't usable yet.** When `Cond::ElapsedDeltaMs`
  returns in Phase 2b, it will need a per-host serialisation guard so
  concurrent scans don't blow up the timing oracle. Not a problem in 2a
  because the flat shape doesn't include cross-step deltas.
- **OOB-dependent rules are skipped.** The `OobInteraction` slot is
  designed but not implemented; an Interactsh-style collaborator service is
  a separate effort.
- **ZAP rules that require Java helpers don't port.** The extractor pulls
  metadata only. Rules whose detection logic relies on jericho-html DOM
  parsing, ZAP's `HtmlParameter` form parser, or session-aware login flows
  will likely never lower cleanly.
- **ZAP regex flavour mismatch.** ZAP uses `java.util.regex` with
  backreferences and lookaround; Rust's `regex` crate is RE2. Phase 2b's
  ZAP lowering will need to fail-skip rules that use unsupported regex
  constructs (estimated 10–20% of ZAP active rules).
- **BCheck JS-snippet rules.** A subset of BChecks embed JavaScript
  expressions inside `if` blocks. Phase 2c will skip-and-log those
  declaratively rather than implementing a JS interpreter.
- **No fan-out yet.** `Payload::FromList` takes the first value only in
  Phase 2a. Real fan-out (one fetch per value) lands in Phase 2b — it
  changes the cardinality of `run_match`'s return value (one
  `Vec<MatchHit>` per call instead of `Option<MatchHit>`).
- **Windows MSVC** is the target most stressed by the recursive serde
  derive. Linux builds run faster end-to-end. The `.cargo/config.toml`
  `RUST_MIN_STACK` setting is required for both, but matters more on
  Windows.

---

## 15. Questions worth asking before extending

- Should `match_spec_json` bake in a schema-version field too, so older
  `corvex-rules` builds reject newer formats cleanly? (Current: implicit
  via `rules_meta.schema_version`.)
- Should the desktop UI gain a "Rules" view that surfaces `rules.sqlite`'s
  contents (filter by source / severity / OWASP, click-through to source
  rule)? Phase 2d is a natural moment to add it.
- For Phase 2d cutover: do we want a CLI flag (`--rules-source=sqlite|bincode`)
  during the soak period, or commit to a hard switch? Hard switch is
  cleaner if the parity test is exhaustive enough.
- Should the embedded rules.sqlite ship via `include_bytes!` (preserving
  the single-binary promise), or as a sibling file extracted on first run
  (mirroring the gzipped vulndb pattern)? Phase 2d decision.
