# Scanner Rule Unification to a Single SQLite Catalog

> Status: **Phase 1 + 2a + 2b + 2c + 2c.1 + 2c.2 + 2c.3 + 2d + 2d.0 (default
> flip + embed rules.sqlite into the desktop binary) complete.** Total
> executable rule coverage is **6,950 / 7,550 (92.1%)**. The desktop
> binary now ships `rules.sqlite` embedded via `include_bytes!`
> (~7.3 MB, +7.6 MB binary growth) and extracts it to `app_data_dir` on
> first launch. The default scan path is now **SQLite-only**: `corvex
> --host X` (or any desktop scan) uses RulesPlugin against all sources;
> TestsPlugin only fires under `--legacy-only` or `--side-by-side`.
> Phase 2d.5 (fixture-target parity diff) is the remaining gating step
> before Phase 2e (delete legacy).
>
> Last updated: 2026-04-29.

This document is the canonical reference for how `corvex/nikto-rust`
consolidates web vulnerability rules from **OWASP ZAP**, **Burp Suite**, and
**Nikto** into a single SQLite catalog (`rules.sqlite`), and how the runtime
scanner consumes that catalog through a multi-step match engine.

It explains what was built, why each piece exists, why the rule counts shift
between source / ingested / executable, what's still deferred, and how to
extend the system in subsequent phases.

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
│   --legacy-only:  TestsPlugin only                                     │
│   default:        side-by-side (RulesPlugin = ZAP+Burp)                │
│   --rules-only:   RulesPlugin only (all sources)                       │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────── Desktop UI ────────────────────────────┐
│   Databases view → "Unified rules" tab                                 │
│   • Total ingested / executable / coverage %                           │
│   • Per-source ingested vs executable + upstream commit SHA            │
│   • Severity distribution                                              │
│   • Build timestamp + schema version + path                            │
└────────────────────────────────────────────────────────────────────────┘
```

### Crate layout

| Crate | Role |
|-------|------|
| **`corvex-core`** | Foundational types. Hosts only the `RuleProvider` trait + `ExecutableRule` struct (with opaque `serde_json::Value` for `match_spec`). **Does not** depend on `corvex-rules`. |
| **`corvex-rules`** | Read-only access to `rules.sqlite` and the `MatchSpec` AST + multi-step engine. Owns the heavy serde-derived types so they don't bloat downstream compile times. Implements `RuleProvider` on `RuleStore`. |
| **`corvex-rules-builder`** | Standalone CLI binary. Reads vendored sources, parses them, normalises into a common schema, lowers detection logic into `MatchSpec`, persists to SQLite. Mirrors the pattern of `vulndb-builder`. |
| **`corvex-plugins`** | Hosts the new `RulesPlugin` (weight 98) alongside the legacy `TestsPlugin` (weight 99). Both gate on `ctx.cli.rules_only` / `ctx.cli.legacy_only`. |
| **`corvex` / `corvex-desktop`** | CLI and Tauri front-end. Look up `rules.sqlite` from the working dir or exe dir at startup, hand a `Arc<RuleStore>` into `ScanCtx`. The desktop additionally exposes the `rules_summary` Tauri command and renders the "Unified rules" tab in the Databases view. |

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
    detection_json   TEXT NOT NULL,       -- per-source raw detection blob,
                                          -- preserved verbatim so future
                                          -- lowering iterations can re-read
                                          -- the original source signal
    source_meta_json TEXT NOT NULL DEFAULT '{}',
    match_spec_json  TEXT,                -- v2: lowered runtime spec; NULL
                                          -- when not yet lowered (see §10)
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

Verbatim copy of the in-repo `program/databases/db_tests` (a 7,284-line CSV
with comment / banner lines stripped during parsing). The builder reads this
canonical location so the CSV format is independent of any future
restructuring of the legacy Perl-style layout.

### 4.2 ZAP

ZAP active and passive scan rules are written in **Java**, so executable
logic doesn't port directly. Instead, an extractor walks the upstream
`zaproxy/zap-extensions` Java sources (`*ScanRule*.java`) and pulls portable
**metadata** + any statically-declared payload arrays + `Pattern.compile()`
regex strings into one JSON file per rule.

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
3. **Lowers** detection logic into `MatchSpec` per source (Phase 2a wires
   Nikto, 2b wires ZAP, 2c wires Burp).
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
in `detection_json = {"kind": "bcheck", "language": "v1-beta|v2-beta", "body": "<raw>", "tags": [...]}`.

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
  ships this; **6,812 / 7,236 (94.1%)** of Nikto rules lower successfully.

- **ZAP** (`kind = "zap_metadata"`): Phase 2b lowers the lowerable subset
  into the same flat shape:
  - Patterns are filtered by Rust regex compile-success (drops Java
    `\1`-backref / lookaround patterns RE2 rejects).
  - Surviving patterns are joined into one alternation under a single
    `Body` matcher.
  - Rules with payloads bind `{{ZAP}}` into `/?fuzz={{ZAP}}` via
    `Payload::FromList`. Result: **17 / 51 (33.3%)**.

- **Burp** (`kind = "bcheck"`): Phase 2c lowers three templates;
  Phase 2c.1 widens predicate coverage from body-only to all four
  matcher kinds:
  1. **Passive single- or multi-predicate.** `given response then if
     {latest.response[.body|.status_code|.headers/Name]} OP "VALUE" then
     report ...` → single GET `/` step + one or more LeafConds AND-joined.
  2. **Active literal-path single-request.** `send request called X:
     path: "/foo" ; if {X.response.body} matches "REGEX" ...` →
     GET `/foo` + LeafConds. Status / header / body / cookie predicates
     all extracted; nested `if` blocks flatten to AND.
  3. **Active path-list run-for-each.** `run for each: paths = "/a", "/b"`
     followed by `send request called X: path: {paths}` → URI becomes
     `{{burp_path}}` with a `Payload::FromList` binding (capped at 16).

  Each `if` line is parsed independently for the four predicate forms:
  `{S} matches "R"` (regex), `{S} is "V"` (equality, anchored regex),
  `{S} contains "V"` (substring, regex-escaped), and `"V" in {S}` (the
  inverted-syntax substring form). Compound predicates (`if A and B`,
  `if A or B`) are still skipped — they need the recursive `Cond`.

  Result: **106 / 263 (40.3%)** — up from 91 in Phase 2c via Phase 2c.1.

Un-lowered rules get `match_spec_json = NULL`. The `idx_rules_executable`
partial index lets the runtime efficiently filter to executable rows only.
The full math behind these drop counts is in §10 below.

### 5.4 CLI surface

```
corvex-rules-builder --sources rules-sources --output rules.sqlite
corvex-rules-builder --sources rules-sources --output rules.sqlite --filter-source zap
corvex-rules-builder --report rules.sqlite
```

The build prints per-source ingest counts, MatchSpec coverage, severity
distribution, OWASP coverage, JSON-validity check, and full `rules_meta`.

---

## 6. The `MatchSpec` AST

Lives in [crates/corvex-rules/src/matcher/spec.rs](crates/corvex-rules/src/matcher/spec.rs).
Two complementary representations live side-by-side:

```rust
pub struct MatchSpec {
    pub steps: Vec<StepSpec>,
    /// Phase 2a–2c.1: flat AND-joined leaves. Cheap and covers the bulk
    /// of every source's lowered rules.
    pub when: Vec<LeafCond>,
    /// Phase 2c.2+: arena-encoded recursive boolean tree for compound
    /// predicates (`if A and B`, `if A or B`, future cross-step deltas).
    /// Optional; absent for simple rules. Runtime AND-joins the verdict
    /// of `when` and `when_cond` so a rule can layer recursive logic on
    /// top of a flat list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_cond: Option<CondGraph>,
}

pub struct CondGraph {
    pub root: u32,
    pub nodes: Vec<CondNode>,
}

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CondNode {
    Leaf(LeafCond),
    All { children: Vec<u32> },   // indices into CondGraph.nodes
    Any { children: Vec<u32> },
    Not { child: u32 },
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

This shape covers everything Phase 2a–2c needed. Phase 2c.5 / 2d.0 will
introduce a recursive `Cond` (with hand-written serde) once a real
upstream rule needs OR / NOT / cross-step deltas — none of the lowered ZAP
or Burp rules so far do.

### 6.1 Why arena-encoded instead of self-referential

A direct recursive enum (`All(Vec<Cond>)`, `Any(Vec<Cond>)`,
`Not(Box<Cond>)`) was attempted during Phase 2a. It compiled on Linux but
on Windows MSVC:

- `recursion_limit` had to jump from the default 128 to 4096 to typecheck.
- Even at 4096, `serde_json::Serializer<&mut Vec<u8>>` monomorphisation
  through the recursive type overflowed the default 1 MB rustc thread
  stack (`STATUS_STACK_OVERFLOW` exit `0xc00000fd`).
- Bumping `RUST_MIN_STACK` to 16 MB via `.cargo/config.toml` lifted the
  hard overflow but compile time grew unbounded — observed ≥60 minutes on
  the single crate without producing an `rmeta`.

**Phase 2c.2 fix:** encode the recursion *in the data* (children are
`u32` indices into a `Vec<CondNode>`) rather than *in the type*
(`Box<Cond>` / `Vec<Cond>`). The `CondNode` enum is non-self-referential,
so serde's derive macro stops at one level and monomorphisation against
`serde_json::Serializer<&mut Vec<u8>>` stays bounded. `corvex-rules`
compiles in **2.4 s cold / 3.3 s with the new types**, identical to the
flat-shape baseline. Hand-written serde impls were not needed.

Tree walks at runtime use a 256-deep recursion guard in `eval_cond`
(`COND_RECURSION_GUARD`); cycles or pathologically deep graphs short-circuit
to `false` rather than blowing the runtime stack.

The `.cargo/config.toml` `RUST_MIN_STACK = 16777216` setting is kept as a
safety net for any future genuinely-recursive types we might add.

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
   - `FromList { values }` → take the first value (Phase 2c.5 will fan
     out — see §15).
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

### 7.1 Future-proofing

The engine signature is already shaped for multi-step: `Vec<StepResult>` is
indexed by `StepId`, not position. When the recursive `Cond` tree lands,
`eval_when` becomes `eval_cond` taking a `Cond` recursively, but the runner
shape (`run_match`) and step pipeline don't change.

The richer variants planned for the future:

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
  Interactsh-style collaborator (deferred).

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

1. If `ctx.cli.legacy_only`, return early.
2. If `ctx.rule_store` is `None`, return early (no rules.sqlite found).
3. Pick the source filter:
   - `ctx.cli.rules_only == true` → `["nikto", "zap", "burp"]` (own
     everything; `TestsPlugin` simultaneously no-ops).
   - default → `["zap", "burp"]` (Nikto stays on `TestsPlugin` during the
     parity period, so no duplicate findings).
4. For each rule: deserialise `match_spec` JSON via
   `corvex_rules::matcher::parse_json`, run `matcher::run_match`, emit a
   `ReportItem` on hit.
5. Severity flows through verbatim from the persisted column.

### 8.4 `TestsPlugin` (legacy) — unchanged except for the gate

[crates/corvex-plugins/src/tests_plugin.rs](crates/corvex-plugins/src/tests_plugin.rs)
keeps its existing bincode `db_tests` flow. The only change is a
short-circuit at the top of `on_scan` that returns early when
`ctx.cli.rules_only` is set — so `--rules-only` produces findings purely
from the new path. Without that flag, behaviour is identical to pre-Phase-2
builds.

### 8.5 Plugin registration

[crates/corvex-plugins/src/lib.rs](crates/corvex-plugins/src/lib.rs)
registers `RulesPlugin` at weight 98, just before `TestsPlugin` at weight 99:

```rust
// Unified rules catalog (ZAP+Burp during the parity period).
Arc::new(rules_plugin::RulesPlugin::default()),
// The big one — runs db_tests. Weight 99 = last.
Arc::new(tests_plugin::TestsPlugin::default()),
```

### 8.6 Desktop integration

Two additions in `corvex-desktop`:

- **`rules_summary` Tauri command** in
  [crates/corvex-desktop/src/commands.rs](crates/corvex-desktop/src/commands.rs).
  Opens `rules.sqlite` read-only on demand, runs aggregate queries
  (per-source counts, severity breakdown, JSON-validity check) plus pulls
  build metadata from `rules_meta`. Returns a typed `RulesSummary` struct.
  Registered in [crates/corvex-desktop/src/main.rs](crates/corvex-desktop/src/main.rs)
  alongside the other `*_summary` commands.
- **"Unified rules" tab** in
  [crates/corvex-desktop/ui/src/components/DatabasesView.tsx](crates/corvex-desktop/ui/src/components/DatabasesView.tsx).
  Eighth tab in the Databases view, joining Web signatures / Probing /
  SCA-VulnDB / Fuzzing / Nuclei / Fingerprints / Exploit-DB. Renders:
  - 6-cell summary grid (total ingested, total executable + coverage %,
    schema version, build timestamp, invalid JSON rows, file path).
  - Per-source coverage table (ingested / executable / coverage % /
    upstream commit).
  - Severity distribution table.
  - Friendly empty state with a "build it with this command" prompt when
    `rules.sqlite` isn't present.

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

Status: **5/5 pass** as of Phase 2c.

### 9.2 Build verification

```
$ cargo run -p corvex-rules-builder -- --report rules.sqlite

[counts by source]
  burp    263
  nikto   7236
  zap     51
  total   7550

[MatchSpec executable coverage]
  burp    121  / 263   (46.0%)
  nikto   6812 / 7236  (94.1%)
  zap     17   / 51    (33.3%)
  total   6950 / 7550  (92.1%)

[OWASP-2025 coverage]
  burp    77   / 263   (29.3%)
  nikto   5361 / 7236  (74.1%)
  zap     51   / 51    (100.0%)

[invalid JSON columns] 0  (expected 0)
```

### 9.3 Smoke test

```
$ ./target/debug/corvex --host http://example.invalid --maxtime 5
- Corvex v0.1.0 (Rust)
+ rules.sqlite loaded (.../rules.sqlite): burp=263, nikto=7236, zap=51
+ scan start: 2026-04-29 ...Z
...
```

The CLI auto-discovers `rules.sqlite` from cwd or exe dir, prints
per-source counts, and proceeds. No regression to the existing scan
pipeline.

### 9.4 Cutover-flag smoke test

```
$ ./target/debug/corvex --host http://target --rules-only   # new path only
$ ./target/debug/corvex --host http://target --legacy-only  # legacy path only
$ ./target/debug/corvex --host http://target                # side-by-side (default)
```

All three accept and load `rules.sqlite` successfully (the legacy mode
loads the file but no plugin reads it). Findings whose `corvex_id` starts
with `zap-` or `burp-` come from the new path; numeric IDs (`000123`)
come from the legacy path.

---

## 10. Why the rule counts don't all match

Each rule passes through three stages that can drop entries:

```
   upstream source       →   ingested (`rules` row)   →   executable
       (raw files)                                       (match_spec_json
                                                          IS NOT NULL)
```

The **ingested** count is what the parser persisted into `rules.sqlite`.
The **executable** count is the subset whose detection logic the lowering
pass could turn into a `MatchSpec` the runtime can fire. Below is a
detailed accounting of why each source loses entries between stages.

### 10.1 Nikto: 7,236 ingested → 6,812 executable (loses 424)

**Source-to-ingested:** The upstream `db_tests` file is 7,284 lines, but
the first 48 lines are comment / banner / blank lines stripped during
parsing. The remaining lines parse cleanly and the resulting ingested
count of 7,236 exactly matches what `corvex-core/build.rs::load_tests`
already reports (`compiled 7236 tests`) for the legacy bincode pipeline.
This is the parity gate — see §9.

**Ingested-to-executable (424 lost, ~5.9%):** The lowering pass
(`lower::lower_nikto`) returns `None` when:

- **`uri_template` is empty.** Synthetic Nikto rules can carry an empty URI
  (rare; usually metadata-only rows). With no URI to fetch, the rule has
  nothing to send. `TestsPlugin` would also skip these because its loop
  builds `Request::new(host, port, method, &uri)` and then short-circuits
  on a missing URI.
- **`corvex_core::dsl::parse(raw_dsl)` fails.** Some rows have malformed
  DSL strings (truncated regex, missing `:` separator after the matcher
  selector, etc.). The legacy `TestsPlugin` wraps `dsl::parse(...)` in
  `let dsl_ast = match dsl::parse(...) { Ok(d) => d, Err(_) => continue };`
  — the same `continue` we apply in the new path.
- **All matchers were filtered out by the parser.** Some rows have a DSL
  that parses to zero leaf matchers (empty `&&`-list). The legacy
  `DslEvaluator::eval` returns `matched=false` on an empty matcher list,
  meaning the rule never fires. The lowering pass refuses to produce a
  `MatchSpec` that always returns `false` and instead leaves it un-lowered
  to make this explicit in the build report.

**Behaviour parity:** the 424 un-lowered Nikto rules are exactly the ones
`TestsPlugin` would also skip via its `continue` paths. No detection
coverage is lost relative to the legacy build — the un-lowered set is
documented in `unlowered_reasons_nikto_json` (`{"nikto_unlowerable": 424}`)
so the build report can flag any drift in future rule-set updates.

### 10.2 ZAP: 142 candidate Java files → 51 ingested → 17 executable

**Source-to-ingested (91 dropped, ~64%):** The upstream
`zaproxy/zap-extensions` repo has 142 files matching `*ScanRule*.java`
under the active and passive scan add-ons. Of those, only **51 expose a
literal-int `getId()` method** the extractor can read — the rest:

- Inherit `getId()` from a parent / abstract base class (the extractor's
  regex requires `public int getId() { ... return <int>; }` to produce a
  descriptor; rules that defer to a base class return value can't be
  uniquely identified without compiling Java).
- Are abstract base classes themselves, named `*ScanRule.java` but never
  instantiated as a leaf rule (e.g. `AbstractAppFilePlugin`).
- Are helper / utility classes whose filename contains "ScanRule" but
  aren't actual rule definitions.

Skipped silently with no log noise — these would never be runnable rules
even with a perfect lowerer.

**Ingested-to-executable (34 dropped, ~67%):** Of the 51 ingested, the
extractor finds *some* extractable detection signal in 21 (~41%); the
lowerer (`lower::lower_zap`) successfully turns 17 of those 21 into a
`MatchSpec`. The 34 that don't lower break down as:

- **No extractable signal at all (~30 rules).** The rule's payload list
  and pattern set live in imperative method bodies, not in static
  declarations: random tokens generated via `UUID.randomUUID()` at scan
  time, request mutation via `getNewMsg().setRequestBody()`,
  payload arrays built up through loops with `String.format` calls. The
  Java AST extractor can't see those values without running the code.
- **All extracted patterns rejected by Rust's `regex` crate (a few of
  the remaining 4).** ZAP rules use `java.util.regex` which supports
  backreferences (`\1`) and lookaround (`(?=...)`); Rust's `regex` is
  RE2 and rejects both. The lowerer filters patterns through
  `regex::Regex::new` and skips the rule if nothing survives.

The 34 un-lowered rules stay catalogued in `rules.sqlite` (severity,
OWASP, CWE, references all populated) and are listed in
`unlowered_reasons_zap_json` (`{"zap_no_extractable_signal": 34}`).

### 10.3 Burp: 263 ingested → 121 executable (loses 142)

**Source-to-ingested:** All 263 BCheck files in the vendored snapshot
ingest cleanly. The Phase 1 parser had a near-miss on 11 files that start
with `#Verified: Yes` comment lines before the `metadata:` block — the
fix to skip leading `#`-comments lifted ingestion to 100%.

**Ingested-to-executable (142 lost, 54%):** Phase 2c.3 widened the
lowerer to handle multi-step BChecks too (every send becomes its own
`StepSpec`; predicates AND-join across steps via leaf retargeting).
The lowerer now covers:

- Passive single- or multi-predicate rules (Phase 2c).
- Active literal-path single-request (Phase 2c).
- Active path-list run-for-each (Phase 2c).
- Compound `if A and B` / `if A or B` predicates lowered into
  `CondGraph` sub-trees (Phase 2c.2).
- Multi-step rules with independent per-step predicates (Phase 2c.3).

The 142 still-un-lowered BChecks now fall into:

- **Mixed `and`/`or` compound rules (~50 files).** The recogniser
  refuses to lower these without explicit operator precedence —
  recognising precedence cleanly would require a real expression
  parser. A small extension that handles parentheses would lift most
  of them; left for a future iteration.
- **Complex `define:` / `run for each:` blocks (~50 files).** Variables
  beyond simple path-string lists — for example
  `define: random_str(6)`, `define: payload = base64_encode(...)`,
  `run for each: header_value = "X-A: 1", "X-B: 2"`. The lowerer's
  `resolve_path_var` only handles quoted-string lists as path values;
  richer variable shapes need their own lowering paths.
- **Multi-step rules with cross-step semantics (~14 files).** Rules
  using `differs from` / `is the same as` / `{OTHER.response.X}` —
  these need explicit mappings to `CondNode::HeaderDiff`,
  `BodyLenDeltaPct Ne 0`, or similar. The cross-step variants exist
  in the engine; only the lowerer pass that recognises these BCheck
  idioms is missing.
- **Other (~28 files).** BCheck JS-snippet rules, rules whose `if`
  predicates target unusual subjects (`{base.url}`, `{base.path}`,
  `{base.host}`), and a handful of edge cases the four-subject
  scanner doesn't recognise.

All 172 un-lowered BChecks are catalogued (severity, name, description,
detection_json with the full body preserved) so future iterations can
re-read the source signal without re-vendoring.

### 10.4 Total

| Stage | Nikto | ZAP | Burp | Total |
|-------|-------|-----|------|-------|
| Upstream source files | 7,284 lines | 142 Java files | 263 .bcheck files | — |
| Ingested into `rules` | 7,236 | 51 | 263 | **7,550** |
| Executable (`match_spec_json IS NOT NULL`) | 6,812 | 17 | 121 | **6,950** |
| Coverage of ingested | 94.1% | 33.3% | 46.0% | **92.1%** |

The big delta in *coverage of ingested* between Nikto (94%) and ZAP/Burp
(~33%) reflects the fundamental difference in how each upstream source
expresses its detection logic:

- **Nikto** is a flat declarative DSL designed for an automated scanner;
  it lowers losslessly because every line is already one rule's
  request + match condition.
- **ZAP** is Java code where most logic lives in method bodies; the
  extractor only recovers what's statically declared, and the lowerer
  only turns that into a runtime spec when there's enough signal.
- **Burp** BChecks are a small declarative DSL but it's expressive
  enough to encode multi-step + compound-predicate rules that the flat
  `Vec<LeafCond>` shape can't represent yet.

Coverage rises monotonically as the lowering passes get smarter
(Phase 2c.5+ adds header/status matchers; the recursive `Cond` work
unlocks multi-step + compound-predicate rules; bind-fan-out lifts
each `Payload::FromList` rule from "fires once" to "fires per value").

---

## 11. Compile-time considerations (Windows MSVC)

Two settings are **load-bearing** for the build to complete on Windows:

### 11.1 `.cargo/config.toml` env

```toml
[env]
RUST_MIN_STACK = "16777216"   # 16 MB
```

Equalises rustc's per-thread stack with Linux's default 8 MB (Windows MSVC
defaults to 1 MB). Required for the future recursive `Cond` enum —
without this, serde monomorphisation overflows mid-compile.

### 11.2 Crate-level `recursion_limit` in `corvex-rules`

Reserved (the bump was pulled when the recursion came out of `Cond`, but
the comment in [crates/corvex-rules/src/lib.rs](crates/corvex-rules/src/lib.rs)
explains the future need). When the recursive `Cond` returns:

```rust
#![recursion_limit = "4096"]
```

belongs at the top of `corvex-rules/src/lib.rs` (not at a module level —
`recursion_limit` is a crate attribute).

### 11.3 Compile times observed

| Stage | Pre-refactor | Post-refactor |
|-------|--------------|---------------|
| `corvex-core` (cold) | 60+ min wedged | 13.7 s |
| `corvex-rules` (cold) | hours / stack overflow | 2.4 s |
| `corvex-rules-builder` | n/a | 9 s |
| Whole CLI workspace | hours | 13.6 s |
| `corvex-desktop` (cold, after Phase 2d UI) | n/a | 1m 47s |

The refactor's two key moves were (a) hosting the heavy types in
`corvex-rules` rather than `corvex-core`, and (b) flattening the recursive
`Cond` to `Vec<LeafCond>` for Phase 2a–2c.

---

## 12. Phased rollout plan

### Phase 1 (complete)

- Build `corvex-rules-builder` with three parsers.
- Vendor sources under `rules-sources/`.
- Produce `rules.sqlite` with normalised columns.
- Verify per-source ingest succeeds end-to-end.

### Phase 2a (complete)

- `corvex-rules` reader crate + `MatchSpec` (flat) + multi-step engine.
- `RuleProvider` trait in `corvex-core`.
- Builder lowering pass for Nikto DSL → MatchSpec.
- `RulesPlugin` registered side-by-side with `TestsPlugin`, scoped to
  `["zap", "burp"]` so no duplicate findings during parity.
- `ScanCtx.rule_store` wired in CLI + desktop.
- Parity test green (5/5).
- 94.1% Nikto MatchSpec coverage.

### Phase 2b (complete)

- Improved `extract_zap.py` to pull every `String[]` array and
  `Pattern.compile("...")` regex from each `*ScanRule.java`.
- `lower::lower_zap` translates the lowerable subset into the flat shape.
- 17 / 51 ZAP rules now executable.

### Phase 2c (complete)

- `lower::lower_burp` parses three BCheck templates: passive
  single-pattern, active literal-path single-request, active path-list
  run-for-each.
- 91 / 263 BCheck rules now executable (body-matcher only).

### Phase 2c.1 (complete) — widen predicate coverage

- Refactored the BCheck lowerer to emit one `LeafCond` per supported
  predicate kind (`Status` / `Body` / `Header` / `Cookie`). Previously
  only `Body` was wired.
- Added recognisers for `{S} is "V"` (equality), `{S} contains "V"`
  (substring), and `{S.headers/NAME}` predicates alongside the existing
  `{S} matches "R"` and `"V" in {S}`.
- Multiple non-compound `if` lines on one rule AND-join automatically
  via the flat `Vec<LeafCond>` shape — handling both sequential and
  nested-`if` BCheck patterns without engine changes.
- **+15 BCheck rules** unlocked (91 → 106). Examples now executable:
  `bcheck-waf-bypass` (status `^403$`), `bcheck-detectRateLimiter`
  (status + body AND), `bcheck-Etcd Server - Unauthenticated Access`
  (status `^200$`), `bcheck-gcp` (GCP metadata endpoint status check),
  `bcheck-unauth-access-to-prometheus-server`,
  `bcheck-OpenID-Dynamic-Client-Registration-Endpoint-Detected`.
- No engine change required — the runtime already evaluated the full
  matcher set; the lowerer just wasn't producing them.

### Phase 2c.2 (complete) — recursive `Cond` for compound predicates

- Added the recursive `Cond` AST as an **arena-encoded** `CondGraph` +
  `CondNode { Leaf | All { children: Vec<u32> } | Any { children:
  Vec<u32> } | Not { child: u32 } }` in
  [crates/corvex-rules/src/matcher/spec.rs](crates/corvex-rules/src/matcher/spec.rs).
  Children are `u32` indices into the graph's `nodes` Vec, so the type
  is **non-self-referential at the type level** — serde's `derive`
  macro doesn't have to expand recursively, sidestepping the Windows
  rustc thread-stack overflow that blocked Phase 2a's first attempt.
  Hand-written serde impls were not needed.
- `MatchSpec.when_cond: Option<CondGraph>` field added with
  `#[serde(default, skip_serializing_if = "Option::is_none")]` — purely
  additive, the existing 6,935 lowered rules continue to round-trip
  through serde unchanged.
- New `eval_cond` evaluator in
  [crates/corvex-rules/src/matcher/engine.rs](crates/corvex-rules/src/matcher/engine.rs)
  — recursive walk over the arena with a 256-deep recursion guard.
  `run_match` evaluates **both** `when` (flat AND-list) and
  `when_cond` (sub-tree) when present and AND-joins the verdicts, so
  a rule can layer compound logic onto the flat list cheaply.
- Lowerer extension: BCheck `if A and B then ...` → `CondNode::All`
  with two leaf children; `if A or B then ...` → `CondNode::Any`. Mixed
  `and`/`or` in one expression is rejected (operator precedence is
  ambiguous without a real parser; that subset is rare in upstream
  BChecks). When multiple `if` lines on one rule each carry a compound
  predicate, the lowerer stitches them under a top-level `All` (their
  semantic AND).
- **+10 BCheck rules** unlocked (106 → 116). Examples:
  - `bcheck-Apache Struts OGNL Console Publicly Accessible` — status
    `^200$` AND body `title>OGNL Console` (3-node graph).
  - 11 rules now carry a `when_cond` sub-tree (one is a rule that
    already lowered flat in 2c.1 and now layers a compound clause too).
- The previous "compound predicates (~70 files)" un-lowered bucket
  shrinks to ~60 — the remaining unlowered compound rules either mix
  `and`/`or`, reference subjects the recogniser doesn't know
  (`{base.url}`, `{base.path}`), or live alongside `define:` blocks
  with non-trivial expressions.

### Phase 2c.3 (complete) — multi-step matchers

Three pieces shipped together:

**1. Cross-step `CondNode` variants** in
[crates/corvex-rules/src/matcher/spec.rs](crates/corvex-rules/src/matcher/spec.rs):

```rust
CondNode::StatusDelta     { a, b, op, value }     // i64 status diff
CondNode::BodyLenDeltaPct { a, b, op, value }     // f64 percent change in body size
CondNode::ElapsedDeltaMs  { a, b, op, value }     // i64 wall-clock delta in ms
CondNode::HeaderDiff      { a, b, name, mode }    // header presence / value diff

pub enum NumOp { Eq, Ne, Lt, Le, Gt, Ge }
pub enum DiffMode { PresenceDiffers, ValueDiffers, AddedInB, RemovedInB }
```

These slot into the existing arena alongside `Leaf` / `All` / `Any` /
`Not`, so the macro-derived serde impls stay cheap (the type is still
non-self-referential — children are still `u32` indices for the boolean
nodes; the cross-step variants reference `StepId`s rather than other
arena indices).

**2. Engine evaluation** — `eval_cond_at` in
[crates/corvex-rules/src/matcher/engine.rs](crates/corvex-rules/src/matcher/engine.rs)
gained four arms that look up both `StepResult`s by id, compute the
delta, and run the comparator. `BodyLenDeltaPct` handles div-by-zero
on empty baselines by reporting `f64::INFINITY` so the comparator
fires when the candidate body is non-empty.

**3. Per-host timing guard** so concurrent traffic doesn't pollute
`ElapsedDeltaMs` rules' timing oracle. A process-wide
`OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>` keys an
async lock per hostname. The guard is taken before *any* HTTP for a
spec carrying `ElapsedDeltaMs` and held for the whole multi-step
sequence, so the baseline and the mutated request can't be interleaved
with another timing-sensitive spec's traffic. `spec_needs_timing_guard`
is the cheap pre-check.

**4. Multi-step lowerer** — `lower_burp_multistep` in
[crates/corvex-rules-builder/src/lower.rs](crates/corvex-rules-builder/src/lower.rs)
now handles BChecks with two or more `send request called X:` blocks:

- Each send becomes its own `StepSpec` keyed by its BCheck name.
- Path resolution mirrors the single-step path; sends with `path: {var}`
  references get a unique `Payload::FromList` bind name per step
  (`burp_path_<send_name>`) so multiple distinct path variables don't
  trample each other.
- Each send's predicates are extracted by the existing
  `extract_burp_predicates` (with `send_name` bound), and the resulting
  leaves are retargeted from the default `r0` step id to the actual
  send's `StepId` via `retarget_leaf` / `retarget_graph` before being
  AND-joined with the other sends' predicates.
- A pre-filter (`has_cross_step_comparison`) refuses BChecks whose
  predicates use `differs from` / `is the same as` / `is {OTHER.response.X}`
  — those rules need *true* cross-step semantics that the per-step lowerer
  would silently mis-translate. Roughly 4 rules out of the 19 multi-step
  BChecks fall into this bucket and remain un-lowered (they're queued for
  a future iteration that explicitly maps `differs from` → `BodyLenDeltaPct
  Ne 0` or similar).

**+5 BCheck rules** unlocked (116 → 121). New executables:

- `bcheck-Nacos-create-user-unauthorized-bypass` — 4-step exploit
  chain (create → delete → create → delete) with status + body
  predicates per step.
- `bcheck-CVE-2023-23752-Joomla-information-disclosure` — 2-step:
  baseline detect (`"joomla-" in body`) + endpoint hit
  (status + multi-key body match).
- `bcheck-CVE-2023-39141 Aria2 WebUI - Path Traversal` — 2-step
  baseline + traversal probe.
- `bcheck-CVE-2025-30208_Vite_dev_server` — 2-step Vite dev-server
  detection.
- Plus a +1 from the escape-handling fix in `extract_quoted_with_len`
  (used to fail on BCheck literals containing escaped quotes such as
  `"\"type\":\"application\""`).

**Bug fixed along the way:** `extract_quoted_with_len` now correctly
tracks consumed byte length even when the quoted body contains escaped
quotes, so `parse_in_payload_value` no longer mis-aligns its tail
match. The previous `find('"')` would return the first escaped quote's
index instead of the closing quote's. Multiple compound predicates
that previously failed now lower cleanly.

### Phase 2d (cutover plumbing — complete)

- **Three CLI flags** in [crates/corvex-core/src/cli.rs](crates/corvex-core/src/cli.rs):
  - `--rules-only` — explicit alias for the new default. RulesPlugin
    handles all sources; TestsPlugin no-ops.
  - `--legacy-only` — RulesPlugin no-ops; TestsPlugin handles Nikto only
    (no ZAP/Burp). Use this as the parity baseline if a default-mode
    run is missing an expected finding.
  - `--side-by-side` — both plugins active; RulesPlugin handles ZAP+Burp
    while TestsPlugin owns Nikto. The pre-Phase-2d.0 default; opt-in now.
- **Both plugins gate** on `ctx.cli.{legacy_only,side_by_side}` at the
  top of `on_scan`. No registry or weight changes.
- **Desktop UI: "Unified rules" tab** in
  [crates/corvex-desktop/ui/src/components/DatabasesView.tsx](crates/corvex-desktop/ui/src/components/DatabasesView.tsx).
  Backed by the `rules_summary` Tauri command. Renders coverage cells,
  per-source table with upstream commit SHAs, severity distribution,
  and a friendly empty state with the build instructions when no
  `rules.sqlite` is present.

### Phase 2d.0 (complete) — flip default to SQLite-only + embed catalog

Two changes that together make `cargo tauri build` ship a self-contained
binary that defaults to the unified-rules path:

**1. Default flip.** Pre-2d.0 the default behaviour was side-by-side
(TestsPlugin Nikto + RulesPlugin ZAP+Burp). Post-2d.0 the default is
**SQLite-only**: every scan uses RulesPlugin against
`["nikto", "zap", "burp"]`; TestsPlugin steps aside unless
`--legacy-only` or `--side-by-side` is explicitly set. The legacy
bincode `db_tests` build path stays compiled in (~7 MB binary cost
unchanged) — flipping back is a one-flag operation, not a rebuild.

**2. Embedded catalog.** `crates/corvex-desktop/build.rs` reads the
repo-root `rules.sqlite` at compile time and writes its path to
`CORVEX_RULES_SQLITE_PATH`. `crates/corvex-desktop/src/rules_embed.rs`
then `include_bytes!`s that file into the binary and exposes a
`resolve_rules_path()` helper that returns the path the runtime should
open. Lookup order:

  1. `<cwd>/rules.sqlite` (power-user override).
  2. `<exe-dir>/rules.sqlite` (sibling-of-binary install layout).
  3. Embedded blob extracted to
     `<app_data_dir>/dev.fazminnizam.corvex-rust/rules.sqlite` on first
     launch (or whenever the on-disk content's length / first 4 KB
     don't match the embedded bytes — catches "user upgraded the
     binary" without a separate version stamp).
  4. None — binary falls back to legacy-only.

Embedding adds **~7.6 MB** to the desktop binary (~7.3 MB blob plus
section padding). The extraction is a one-shot ~5 ms write on first
launch; subsequent launches see the file and skip the write.

If the repo-root `rules.sqlite` is missing at build time (fresh clone),
`build.rs` emits an empty placeholder and prints a `cargo:warning`. The
runtime detects the empty embed via a SQLite-header sniff and falls
through to the cwd / exe-dir / "no catalog" cases — the build never
fails on a fresh checkout.

**`cargo tauri build`** therefore now produces a single bundle that:
- Ships every Nikto / ZAP / Burp rule in one file (no separate
  `rules.sqlite` companion).
- Defaults to running every rule through the unified path.
- Surfaces all three sources' counts under Databases → Unified rules
  immediately on first launch (the tab calls `rules_summary`, which
  uses the same `resolve_rules_path()` helper, so it sees the
  extracted blob without any other code change).

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
- **Bind fan-out** lift: `Payload::FromList` runs the step once per
  value rather than just the first. Required for active fuzzing where
  each payload value should produce its own request and potentially
  its own finding.

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

- **Recursive `Cond` enum** with hand-written serde impls for ZAP / Burp
  rules that need OR / NOT trees or cross-step deltas. Will lift Burp
  multi-step + compound-predicate coverage and unlock proper SQLi
  reflection / time-based ZAP rules.
- **OOB collaborator service** (Interactsh-style) so
  `Cond::OobInteraction` becomes executable.
- **ZAP regex flavour translation** (java.util.regex → Rust's RE2):
  rewriting backref / lookaround patterns to RE2-compatible forms so a
  larger ZAP subset survives the regex-compile filter.
- **BCheck "v2-beta" full DSL coverage** including arbitrary `define:` /
  `run for each:` blocks beyond simple path lists.
- **Header / status-code matchers in BCheck lowering**, increasing the
  Burp coverage past the body-only template.
- **Desktop UI: rebuild button** on the Rules tab that invokes
  `corvex-rules-builder` (mirroring the Exploit-DB Re-sync button), and
  a checkbox in the Web Scan form to set `--rules-only` / `--legacy-only`
  from the GUI.

---

## 13. Files of interest

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
                                            # (Nikto + ZAP + Burp passes)
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
rules-sources/zap/*.json                    # 51 rule descriptors
rules-sources/burp/COMMIT
rules-sources/burp/**/*.bcheck              # 263 BCheck files

.cargo/config.toml                          # RUST_MIN_STACK=16MB

rules.sqlite                                # built catalog, tracked in git
                                            # so fresh clones get a working
                                            # unified-scanner path without
                                            # running the builder first
```

### Modified

```
Cargo.toml                                  # workspace members + deps
.gitignore                                  # tracks /rules.sqlite, ignores
                                            # only its in-flight side files
crates/corvex-core/src/lib.rs               # pub mod matcher
crates/corvex-core/src/scan.rs              # ScanCtx.rule_store
crates/corvex-core/src/cli.rs               # --rules-only + --legacy-only
crates/corvex-plugins/src/tests_plugin.rs   # ctx.cli.rules_only gate
crates/corvex/Cargo.toml                    # depends on corvex-rules
crates/corvex/src/main.rs                   # rule_store loading
crates/corvex-desktop/Cargo.toml            # depends on corvex-rules
crates/corvex-desktop/src/commands.rs       # rule_store loading +
                                            # rules_summary command
crates/corvex-desktop/src/main.rs           # invoke_handler registers
                                            # rules_summary
crates/corvex-desktop/ui/src/api.ts         # RulesSummary types +
                                            # rulesSummary() wrapper
crates/corvex-desktop/ui/src/components/DatabasesView.tsx
                                            # "Unified rules" tab
crates/corvex-plugins/Cargo.toml            # depends on corvex-rules
crates/corvex-plugins/src/lib.rs            # register RulesPlugin
```

### Untouched

- `crates/corvex-core/build.rs` — the bincode `databases.bin` pipeline
  remains in place during Phase 2.
- `crates/corvex-core/src/db/types.rs` — `TestRow` and friends are
  unchanged.
- All other `corvex-plugins/*` modules.

---

## 14. Operational notes

### 14.1 Building `rules.sqlite`

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

### 14.2 `rules.sqlite` location at runtime

The CLI and desktop binaries look for `rules.sqlite` in:

1. The current working directory.
2. The directory containing the binary itself.

If neither location holds the file, the binary logs a debug message and
proceeds without it (legacy `TestsPlugin` keeps running). This makes the
file optional for development and easy to swap during testing.

The file is **tracked in git** at the repo root (`/rules.sqlite`). Fresh
clones get a working unified-scanner path immediately without needing to
run the builder first. The canonical workflow:

1. Edit `rules-sources/` (vendor a new ZAP commit, edit a Burp BCheck,
   improve `lower::lower_*`, etc.).
2. `cargo run -p corvex-rules-builder -- --sources rules-sources --output rules.sqlite`
3. Commit the regenerated `rules.sqlite` alongside whatever source change
   provoked the rebuild.

SQLite's in-flight side files (`-journal`, `-wal`, `-shm`) stay
gitignored — only the finished catalog should land in git.

**For `cargo tauri dev` testing,** the desktop process's exe lives at
`target/debug/corvex-desktop.exe`, so dropping a copy of `rules.sqlite`
next to it ensures the catalog loads regardless of which working directory
the user launches the dev tooling from:

```
cp rules.sqlite target/debug/rules.sqlite
```

The repo-root copy and the `target/debug/` copy can coexist; the cwd
candidate is checked first, so when launched from the repo root the
top-level copy wins. When launched from elsewhere (an IDE deep-link,
another terminal pane, etc.) the exe-dir fallback succeeds.

### 14.3 Refreshing vendored sources

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
`MatchSpec executable coverage` numbers in this doc and §10 if they
materially shift.

### 14.4 Adding a new rule source

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
6. Update `RulesPlugin`'s default source filter if you want the new source
   to fire in the side-by-side period.

### 14.5 Verifying the unified path is active

For the CLI:

```
RUST_LOG=info,tests_plugin=debug,rules_plugin=debug \
  ./target/debug/corvex --host http://target --rules-only

# Look for: "rules_plugin: running N rules from unified store"
```

For the desktop, open Databases → **Unified rules** tab. The 6-cell summary
shows live counts off whichever `rules.sqlite` was loaded; the per-source
table shows ingested vs executable per source with the upstream commit
short-SHA next to each. If the tab shows a "build it with this command"
empty state, no `rules.sqlite` was found in cwd or exe-dir.

Findings emitted via `RulesPlugin` carry a `corvex_id` of the form
`<source>-<rule_id>`:

- `nikto-000123` (only when `--rules-only` is set)
- `zap-40008`
- `burp-bcheck-leaked-aws-token`

Findings from the legacy `TestsPlugin` carry the bare numeric Nikto ID
(e.g. `000123`).

---

## 15. Known limitations

- **Phase 2d.5 hasn't run yet.** Until the fixture-target parity test
  passes, `--rules-only` is opt-in and the default stays side-by-side.
  Nothing forces the legacy path to retire.
- **Bind fan-out is not wired.** `Payload::FromList` runs the step once
  with the first value — meaningful for active fuzzing rules where each
  payload should produce its own request. Phase 2d.5 deliverable.
- **OOB-dependent rules are skipped.** The `OobInteraction` slot is
  designed but not implemented; an Interactsh-style collaborator service
  is a separate effort.
- **ZAP rules that require Java helpers don't port** (~30 rules out of 51
  ingested). Logic relying on jericho-html DOM parsing, ZAP's
  `HtmlParameter` form parser, session-aware login flows, or runtime
  payload generation can't be expressed without compiling Java. Section 10
  has the full breakdown.
- **ZAP regex flavour mismatch.** A small number of ZAP rules' patterns
  use backreferences or lookaround that the Rust `regex` crate (RE2)
  rejects. The lowerer filters these via `regex::Regex::new` and skips
  the rule if nothing survives. Future work: rewrite a subset of these
  patterns into RE2-compatible forms.
- **BCheck rules with multi-step / compound predicates / complex `define:`
  blocks (~172 of 263) need richer matcher support** — recursive `Cond`,
  cross-step deltas, header/status matchers in the lowerer. Section 10
  has the breakdown by reason.
- **Recursive `Cond` deferred.** None of the lowered rules so far have
  needed it, but it's the unblocker for cross-step ZAP / Burp rules.
  Bringing it back will use hand-written `Serialize` / `Deserialize`
  impls (not derive) so `corvex-rules` keeps compiling fast on Windows
  MSVC.
- **No fan-out yet.** See bind fan-out above.
- **Windows MSVC** is the target most stressed by the recursive serde
  derive. Linux builds run faster end-to-end. The `.cargo/config.toml`
  `RUST_MIN_STACK` setting is required for both, but matters more on
  Windows.

---

## 16. Questions worth asking before extending

- Should `match_spec_json` bake in a schema-version field too, so older
  `corvex-rules` builds reject newer formats cleanly? (Current: implicit
  via `rules_meta.schema_version`.)
- ✅ ~~Should the desktop UI gain a "Rules" view?~~ — answered in Phase 2d:
  shipped as a tab in the existing Databases view rather than a top-level
  sidebar entry, since the data is read-only.
- For Phase 2e cutover: do we want a CLI flag (`--rules-source=sqlite|bincode`)
  during the soak period, or commit to a hard switch? Hard switch is
  cleaner once the parity test is exhaustive enough; the existing
  `--legacy-only` keeps the bincode path callable post-cutover for
  bisecting any regression.
- Should the embedded rules.sqlite eventually ship via `include_bytes!`
  (preserving the single-binary promise), or stay as a sibling file
  extracted on first run (mirroring the gzipped vulndb pattern)? Phase 2e
  decision; today the file is always external and discovered at startup.
- For a "Rebuild rules" button on the Rules tab — same UX as Exploit-DB's
  Re-sync — should it shell out to `corvex-rules-builder` or call into the
  builder library in-process? In-process is cleaner but requires turning
  the builder's `main.rs` driver code into a re-usable `lib.rs` first.
