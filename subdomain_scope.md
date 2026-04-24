# Plan — Subdomain / DNS Recon feature (subfinder + dnsrecon inspired)

## Context

The user wants to bring the useful core of two well-known recon tools
into corvex-desktop:

- **subfinder** (ProjectDiscovery) — passive subdomain enumeration
  against many public sources (cert-transparency logs, DNS
  aggregators, WHOIS providers). No target traffic; just aggregation.
- **dnsrecon** (darkoperator) — active DNS reconnaissance: record
  enumeration (A/AAAA/MX/NS/TXT/SOA/CNAME), wordlist-based subdomain
  brute force, zone-transfer attempts, reverse DNS sweeps.

These are the natural companion to the proxy + checks + fuzzer flow
that already ships: before you can audit an app, you usually want to
know *which hosts belong to the target*. Today that step happens in a
separate terminal.

**Scope reality after scouting:** a surprising amount of the backend
is already in place.

- `crates/corvex-core/src/dns.rs` already ships: `lookup_records`
  (A/AAAA/MX/NS/TXT/CNAME/SOA), `try_zone_transfer` (AXFR),
  `reverse_lookup`, **`brute_subdomains` with a tokio `Semaphore`
  pool**, and `check_spf_issues`. All async, hickory-resolver based.
- `hickory-resolver` is already in the workspace Cargo.lock.
- The Tauri probe-job pattern (`ProbeRegistry` + `CancellationToken`
  + `tauri::async_runtime::spawn` + live progress events) is exactly
  the shape we want for recon jobs.
- `reqwest` is available for the passive-source HTTP calls (crt.sh,
  HackerTarget, etc.) — no new dep.
- Sidebar already has a natural slot alongside Probing in the "Engine"
  section.

**What's missing:** passive-source clients (none exist), a Tauri
command surface, a SQLite persistence pair for recon runs, the
cross-tool integrations (Send-to-Checks / Send-to-Proxy-scope /
Send-to-Fuzzer on a recon row), and the whole UI view.

**Intended outcome:** a "Recon" top-level view in the sidebar that
takes a domain, runs passive enumeration across 3 keyless sources in
parallel, surfaces discovered subdomains with source attribution +
resolved A/AAAA, and offers an explicit "active" mode that runs
wordlist brute-force + record enumeration + optional reverse /24.
Results persist in the app's SQLite DB so History shows past runs.
Per-row actions send discovered hosts into the existing Proxy scope
rules, Checks, or Fuzzer.

---

## Recommended approach

**Extend `corvex-core` — don't spin up a new crate.** The DNS
primitives are already there; this is one new module
(`recon/passive.rs`) plus a small runner. Add the rest of the wiring
in the existing `corvex-desktop` crate.

### Architecture (v1)

```
corvex-core/src/
  dns.rs                           # EXISTING — keep; extend with
                                   # wildcard detection + subdomain
                                   # record enumeration helper
  recon/                           # NEW
    mod.rs                         # ReconRunner, ReconEvent enum
    passive.rs                     # Trait PassiveSource + 3 impls

corvex-desktop/src/
  recon_state.rs                   # NEW — mirrors probe_state.rs
  recon_store.rs                   # NEW — SQLite persistence
  recon_cmd.rs                     # NEW — Tauri commands
  main.rs                          # register registry + commands + DB

corvex-desktop/ui/src/
  components/ReconView.tsx         # NEW — top-level view
  components/Sidebar.tsx           # extend — add "Recon" entry
  App.tsx                          # extend — route the new view
  api.ts                           # extend — recon_start/stats/cancel/list
```

### Passive sources (all keyless — v1)

User-confirmed set: **crt.sh + AlienVault OTX + CertSpotter**.
HackerTarget (rate-limited) and Wayback Machine (noisy URL→host
extraction) are deferred to v1.1.

1. **crt.sh** — `https://crt.sh/?q=%25.{domain}&output=json`, returns
   JSON array with `name_value`. The canonical source. Splits multi-
   value cells on newlines. Deduplicate + strip leading `*.`.
2. **AlienVault OTX** — `https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns`,
   returns JSON with `passive_dns: [{hostname, ...}]`.
3. **CertSpotter** — `https://api.certspotter.com/v1/issuances?domain={d}&expand=dns_names&include_subdomains=true`,
   returns array of `{dns_names: [...]}`.

Each source implements a trait:

```rust
pub trait PassiveSource: Send + Sync {
    fn name(&self) -> &'static str;
    /// Returns an iterator (Vec for simplicity v1) of hostnames.
    async fn enumerate(&self, domain: &str, client: &reqwest::Client)
        -> Result<Vec<String>, ReconError>;
}
```

All three run concurrently via `futures::future::join_all`; partial
failures don't abort (dnsrecon / subfinder both behave this way).

### Active mode (v1)

Toggled on separately from passive. Runs in this order:

1. **`lookup_records(domain)`** (existing) — A/AAAA/MX/NS/TXT/CNAME/SOA
2. **`try_zone_transfer(domain)`** (existing) — records a finding if
   the server responds, otherwise no-op (expected on modern DNS)
3. **`brute_subdomains(domain, wordlist, 500)`** (existing, bumped
   concurrency from whatever caller passes). Before the brute-force
   fires, add new helper `detect_wildcard(domain)` — resolve
   `<random-64-char-string>.{domain}`; if it answers, capture the IP
   and filter brute-force hits that match it (NXDOMAIN-equivalent
   suppression).
4. **For each discovered subdomain** (passive + brute) — optionally
   resolve A/AAAA/CNAME to surface IPs in the results grid.
5. **(Off by default, explicit checkbox) Reverse DNS** on the /24
   around each discovered A record. Noisy; clearly labeled.

Wordlist: ship a small embedded default (~200 common names) in
`corvex-core/data/subdomains.txt` included at compile time via
`include_str!`. Let the user point at a larger file path in the UI
for real runs.

### Progress events (mirror probe pattern)

Single event name per run: `recon://event` with a tagged payload:

```rust
enum ReconEvent {
    SourceStarted { source: &'static str },
    SourceFinished { source: &'static str, found: usize, error: Option<String> },
    SubdomainDiscovered { host: String, sources: Vec<String>, ips: Vec<String> },
    RecordDiscovered { name: String, record_type: String, value: String },
    WildcardDetected { ip: String },
    BruteProgress { tested: usize, total: usize, found: usize },
    Complete { found_total: usize, duration_ms: u64 },
    Failed { error: String },
}
```

UI listens once, filters by `run_id` (ship it in every payload).

### Persistence

Two new tables in the existing `history.sqlite` (reuse the file the
HistoryDb already opens):

```sql
CREATE TABLE IF NOT EXISTS recon_runs (
    id TEXT PRIMARY KEY,          -- uuid
    domain TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    status TEXT NOT NULL,         -- 'running' | 'complete' | 'cancelled' | 'failed'
    passive_sources TEXT,         -- CSV of enabled source names
    active_enabled INTEGER NOT NULL,
    wildcard_ip TEXT,
    found_subdomains INTEGER NOT NULL DEFAULT 0,
    found_records INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE TABLE IF NOT EXISTS recon_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    kind TEXT NOT NULL,           -- 'subdomain' | 'record' | 'zone-transfer'
    name TEXT NOT NULL,           -- subdomain fqdn, or record owner
    value TEXT,                   -- IP, CNAME target, TXT content, etc.
    record_type TEXT,             -- A/AAAA/MX/… for records; NULL for subdomains
    sources TEXT,                 -- CSV of passive sources (subdomain kind)
    discovered_at INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES recon_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_recon_findings_run ON recon_findings(run_id);
```

### Tauri commands

```rust
recon_start(params: ReconParams) -> ReconRunId     // uuid
recon_cancel(id: ReconRunId) -> bool
recon_status(id: ReconRunId) -> ReconStatus        // snapshot
recon_runs_list(limit) -> Vec<ReconRunSummary>     // history
recon_findings_for_run(id: ReconRunId) -> Vec<ReconFinding>
```

`ReconParams` shape:

```typescript
{
  domain: string;
  passive_sources: string[];     // subset of the 3 above
  active: boolean;
  wordlist_path?: string;        // falls back to embedded default
  reverse_dns: boolean;
  max_concurrent: number;        // default 500
}
```

### Cross-tool integration (the "seamless" part)

User-confirmed set for v1: **Send to Proxy scope + Send to Checks +
Send to Fuzzer**. CSV export deferred to v1.1 (the SQLite `recon_findings`
table has everything a follow-up export needs).

On any row in the results grid, a kebab menu / button row:

- **Send to Proxy scope** — appends an include rule
  `{host: <discovered>, path_regex: null, port: null}` via the
  existing `scope_set` command. Reuses the infrastructure shipped in
  the scope-rules work. Bulk version: "Add all N in-scope".
- **Send to Checks** — for subdomains that resolved, synthesise an
  Exchange (same path as OpenAPI/Postman import:
  `ExchangeOrigin::Imported { source: "recon" }`, `GET /`, scheme
  https if port 443 else http) and push via `record_exchange`, then
  navigate to the Proxy Checks tab with the row preselected. Requires
  an active proxy session — error with a clear message if there isn't
  one.
- **Send to Fuzzer** — reuse the existing `FuzzerSeed` lift path
  shipped earlier; open Active Fuzzing with host prefilled.

### UI view — one tab or tabbed?

Single-pane scroll:

```
Recon
┌──────────────────────────────────────────────────────────┐
│ Domain: [example.com                          ]           │
│                                                           │
│ Passive sources:                                          │
│   ☑ crt.sh  ☑ AlienVault OTX  ☑ CertSpotter               │
│                                                           │
│ ☐ Active mode (DNS records + brute-force)                 │
│    Wordlist: [<default>                    ] [Browse…]    │
│    Concurrency: [500▾]  ☐ Reverse /24 (noisy)             │
│                                                           │
│ [ Start recon ]   [ Cancel ]                              │
│                                                           │
│ Status: crt.sh ✓ (187)  AlienVault ✓ (42)  ...            │
│ Wildcard: *.example.com → 1.2.3.4 (filtered)              │
│                                                           │
│ Results: 214 subdomains, 7 records                        │
│  ┌─────────────────┬─────────────┬──────────┬──────────┐  │
│  │ host            │ sources     │ ips      │ actions  │  │
│  │ api.example.com │ crt, OTX    │ 1.2.3.4  │ [▾]      │  │
│  │ ...             │             │          │          │  │
│  └─────────────────┴─────────────┴──────────┴──────────┘  │
│ [ Add all to Proxy scope ]  [ Send all to Checks ]        │
└──────────────────────────────────────────────────────────┘
```

History mode (past runs) — a sub-tab or a toggle chip above the form.
Click a past run → results grid loads from `recon_findings_for_run`
exactly the same way.

### Critical files to modify or create

**New (corvex-core):**
- `crates/corvex-core/src/recon/mod.rs`
- `crates/corvex-core/src/recon/passive.rs`
- `crates/corvex-core/data/subdomains.txt` (~200 entries)

**Modified (corvex-core):**
- `crates/corvex-core/src/lib.rs` — `pub mod recon;`
- `crates/corvex-core/src/dns.rs` — add `detect_wildcard` +
  `lookup_a_aaaa_cname` helpers; the existing `brute_subdomains`
  takes a new optional wildcard-IP filter via a small wrapper

**New (corvex-desktop):**
- `crates/corvex-desktop/src/recon_state.rs` (mirror `probe_state.rs`)
- `crates/corvex-desktop/src/recon_store.rs` (schema + CRUD)
- `crates/corvex-desktop/src/recon_cmd.rs` (Tauri commands)

**Modified (corvex-desktop):**
- `crates/corvex-desktop/src/main.rs` — register registry, new
  commands, event bridge
- `crates/corvex-desktop/src/history.rs` — extend schema or delegate
  to recon_store (expose the same `HistoryDb` connection)

**New (ui):**
- `crates/corvex-desktop/ui/src/components/ReconView.tsx`

**Modified (ui):**
- `crates/corvex-desktop/ui/src/components/Sidebar.tsx` — add `recon`
  to the `View` union + a nav entry after Probing
- `crates/corvex-desktop/ui/src/App.tsx` — route `view === "recon"`,
  thread a `reconSeed` state if we want deep-links from other tabs
- `crates/corvex-desktop/ui/src/api.ts` — types + wrappers for the 5
  new commands
- `crates/corvex-desktop/ui/src/components/HelpView.tsx` — new sub-head
  explaining Recon + scenario recipe + glossary terms

### Existing functions/utilities to reuse

- `corvex_core::dns::lookup_records` — A/AAAA/MX/NS/TXT/CNAME/SOA
- `corvex_core::dns::try_zone_transfer` — AXFR attempt
- `corvex_core::dns::reverse_lookup` — IP → PTR
- `corvex_core::dns::brute_subdomains` — wordlist brute-force with
  Semaphore pool
- `corvex_core::dns::check_spf_issues` — SPF hygiene findings
- `hickory_resolver::TokioResolver` — already configured via the
  `resolver()` helper in `dns.rs`
- `reqwest` — already a workspace dep; use for the passive sources
- `tokio_util::sync::CancellationToken` + `uuid::Uuid` — same pattern
  as `ProbeRegistry`
- `tauri_plugin_dialog` — already wired for save/open (we used it for
  HAR export + spec import). Reuse for wordlist picker
- `history::HistoryDb` — open the connection once; recon_store opens
  its own handle to the same file (WAL-safe, same pattern as ProxyDb)
- `ExchangeOrigin::Imported` + `ProxyState::record_exchange` — reuse
  the path OpenAPI import already uses, for the Send-to-Checks action
- Existing `scope_set` Tauri command — reuse for Send-to-Proxy-scope

### Scope non-goals (v1 cut line)

- HackerTarget + Wayback Machine passive sources (deferred to v1.1
  per user choice).
- Keyed passive sources (Shodan, Censys, VirusTotal). Schema leaves
  room for a later `provider-config` settings pane.
- CSV export of recon results (deferred to v1.1 — the SQLite rows
  are the source of truth, export is a convenience).
- DNSSEC / NSEC zone walking. Needs an NSEC state machine.
- Cache snooping (requires pointing at a victim resolver).
- TLD expansion / search-engine scraping (noisy, rate-limit-prone).
- Inline bulk scan of every discovered subdomain from the recon tab.
  We surface the Send-to-X action so the user makes that choice per
  target.

---

## Verification

1. **Unit tests (corvex-core)**
   - `recon::passive::tests::parses_crtsh_json` — feed canned JSON,
     verify dedup + wildcard-prefix stripping
   - `recon::passive::tests::parses_alienvault_json`
   - `recon::passive::tests::parses_certspotter_json`
   - `dns::tests::wildcard_detection_returns_ip_when_wildcard_present`
     — use a domain where we know the behaviour (or mock via hickory's
     `MockResolver` trait pattern; or just gate on an env flag so the
     test is skipped without network)

2. **Unit tests (corvex-desktop)**
   - `recon_store::tests::run_round_trip` — insert a run + findings,
     read back, assert counts
   - `recon_store::tests::cascade_on_run_delete` — delete run,
     verify findings gone

3. **Manual end-to-end**
   - `cargo check -p corvex-core -p corvex-desktop` — clean
   - `cargo test -p corvex-core -p corvex-desktop` — all green
   - `npx tsc -b` in `crates/corvex-desktop/ui` — clean
   - Launch the app, pick a domain with known public subdomains (e.g.
     `hackerone.com` or `google.com`), run passive-only — expect
     dozens of hits from crt.sh / CertSpotter alone within seconds
   - Run with Active enabled + default wordlist — expect brute-force
     progress ticking in real time, wildcard filter firing if target
     has a wildcard record
   - Click **Add all to Proxy scope** on discovered rows — switch to
     Proxy Settings → Scope rules, confirm N new include rules
   - Click **Send to Fuzzer** on one row — Fuzzing view opens with
     host pre-filled, same behaviour as the existing Traffic
     Send-to-Fuzzer
   - Open History view → past recon runs visible, click one →
     results grid rehydrates

4. **Performance check** — run against a domain with >1k known
   subdomains (e.g. a big SaaS) using crt.sh + CertSpotter + a 5k
   wordlist at concurrency 500. Target: under 60s wall-clock, UI
   responsive throughout, memory bounded.

5. **Help section update** — as per the standing feedback memory,
   ship a HelpView sub-head + scenario recipe + glossary entry for
   the Recon view in the same pass.

6. **Progress.md** — add a new `### Recon & DNS` heading under
   `⏳ Pending` listing the v2 items we explicitly cut (keyed
   sources, DNSSEC walking, cache snooping), and check off the v1
   item once shipped. Given the scope, this should land as a new
   Progress.md bullet rather than hiding inside "Proxy listener —
   functional gaps".
