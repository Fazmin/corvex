# corvex-desktop — Progress tracker

Living checklist of what's shipped, what's pending, and what's
explicitly deferred. Update this file as items close out.

> **How to use:** tick the `- [ ]` box to `- [x]` when an item is
> complete. Add a date + short note under the item (indented) if the
> "done" state has caveats. New work lands under the **Pending** or
> **Deferred** sections at the bottom — don't retrofit items into the
> Shipped list after the fact without a commit reference.

---

## ✅ Shipped

### Phase 1 — Proxy foundations

- [x] `corvex-proxy` crate scaffold with CA, exchange, scope, store
      modules
- [x] OpenSSL-based MITM listener (`hyper` + `tokio-openssl`)
- [x] CONNECT tunnelling and SNI-driven leaf-cert minting
- [x] Batched SQLite writer for captured exchanges
- [x] Live broadcast channel bridged to the
      `proxy://exchange-new` Tauri event
- [x] Tauri commands: `proxy_start` / `proxy_stop` /
      `proxy_status` / `proxy_export_ca_pem` /
      `exchanges_list` / `exchange_get`
- [x] Sidebar entry (labelled **Intercept**) + `ProxyView` shell with
      5 tabs
- [x] Settings sub-tab with guided CA export + per-OS install
      commands + per-browser walkthroughs
- [x] Automated plain-HTTP smoke test (`plain_http_smoke.rs`)

### Phase 2 — Intercept and Replay

- [x] `InterceptQueue` with oneshot-based pause + 5-min auto-forward
- [x] Request-phase intercept integration in the listener
- [x] Intercept tab: mode chips, pending queue, raw-bytes editor,
      Forward / Forward edited / Drop / Drop all
- [x] Replay engine + `replay_send` Tauri command
- [x] Replay tab: request editor, response viewer, edit detection
- [x] Send-to-Replay / Send-to-Checks actions on Traffic rows
- [x] Intercept + Replay integration tests
      (`intercept_replay.rs`, 3 tests)
- [x] Dedupe guard so React strict-mode double-mount doesn't
      produce duplicate rows in Traffic

### Phase 3A — Coded OWASP checks

- [x] `corvex-intel` crate with OWASP header baseline + payload
      banks + XSS context breakers + open-redirect sentinel
- [x] `corvex-checks` crate with `PassiveCheck` / `ActiveCheck`
      traits + `CheckRegistry`
- [x] 5 passive checks: Security Headers, Verbose Errors,
      Version Disclosure, Insecure Cookies, Stack Fingerprint
- [x] Banner CVE cross-reference passive check
      (`banner-cve`, A03) — Stack Fingerprint → vulndb lookup
      via curated `WEB_TECH_MAP` (70+ Wappalyzer-product → CPE
      mappings in `corvex-core::sca::cpe_map::lookup_web_tech_cpe`),
      CVSS-v3.1-mapped severity (Crit ≥9.0, High ≥7.0, Med ≥4.0,
      Low >0), EPSS + percentile evidence when present,
      char-boundary-safe 500-char description trimming,
      25-findings cap per exchange; disabled cleanly when
      vulndb is missing (one-time warning on startup).
- [x] 7 active checks: Reflected XSS, Error-based SQLi,
      Open Redirect, Boolean-blind SQLi, Time-based SQLi,
      SSRF, Hidden Parameter Discovery — plus the
      `nuclei-active` umbrella runner. Individual entries:
  - Boolean-blind SQLi (`boolean-blind-sqli`, A05) — trigram
    page-ratio oracle with four SQL boundary variants (numeric /
    single-quote / double-quote / paren-quote), three-ratio
    gating (true ≥0.90, false ≤0.80, gap ≥0.05),
    baseline-stripping via
    `corvex_core::sqli::detection::remove_dynamic_content`,
    original-value-preserving probes.
  - Time-based blind SQLi (`time-based-sqli`, A05) — two-shot
    oracle (4s probe + 7s confirmation) with per-DBMS sleep
    payloads (MySQL/PostgreSQL/MSSQL/Oracle), 800ms MARGIN_MS
    jitter guard, MSSQL stacked-trailer suppression,
    stop-on-first-hit per parameter.
  - SSRF (`ssrf`, A10) — 8 probes across AWS IMDSv1 (+ IAM
    creds endpoint), GCP computeMetadata, Azure IMDS,
    DigitalOcean, plus loopback + decimal-IP/localhost
    filter-bypass variants. Body-marker oracle with
    baseline suppression, URL-shape heuristic, Critical
    severity on AWS/GCP/Azure hits.
  - Hidden-parameter discovery (`hidden-params`, A05) —
    curated 13-group / ~220-name wordlist in
    `corvex-intel::hidden_params`, two-pass probing
    (`1`-prefixed random canary → truthy fallback),
    control-probe jitter suppression, per-class evidence
    (admin-access / debug / method-override / feature-flag /
    redirect-target / ssrf-shaped / …). Force multiplier
    for every other active check.
  - Active Nuclei template execution (`nuclei-active`, A03) —
    umbrella active check that drives the existing
    `corvex_nuclei::Executor` against the target's base URL,
    default severity+KEV-tag filter (kev / rce / auth-bypass /
    ssrf / sqli / lfi / rfi / xxe / command-injection /
    fileupload / deserialization / takeover), 300-template
    hard cap, shared 8-way request semaphore. Findings emit
    with check id `nuclei-active:<template-id>` distinct from
    passive `nuclei:<template-id>` rows. Env toggle
    `NUCLEI_ACTIVE_INCLUDE_ALL=1` drops the filter for full
    sweeps.
- [x] Shared active-check helpers — `with_param_value()` that
      preserves the original parameter value plus
      `SQLI_BOUNDARIES` (numeric / single-quote / double-quote /
      paren-quote) in `corvex-checks::active` mod.
- [x] `CheckBridge` hooks proxy broadcast → passive run →
      `proxy://scan-finding` + SQLite persist, opens shared
      `VulnDb::open_default()` at startup for banner-cve and
      degrades gracefully when the DB is missing.
- [x] Tauri commands: `checks_list` / `findings_for_exchange` /
      `findings_for_session` / `checks_run`
- [x] Checks tab UI: OWASP-grouped library, target list, findings
      stream, per-check toggles, library search — new checks
      auto-surface via dynamic `checks_list` rendering, no UI
      code changes required
- [x] Test coverage for Phase 3A — 131 tests total across
      corvex-checks / -core / -intel (18 new integration tests
      in `banner_cve.rs`, `sqli_blind.rs`, `ssrf.rs`,
      `hidden_params.rs`, `nuclei_active.rs`; 23 new inline
      unit tests across the new checks + wordlist). Hyper stubs
      exercise each check end-to-end through the real
      CheckRegistry dispatch path.

### Phase 3B — Data-driven datasets

- [x] Wappalyzer-schema fingerprint engine +
      `FingerprintLike` trait
- [x] Compile-time-embedded Wappalyzer dataset
      (HTTPArchive/wappalyzer vendored, ~3,992 fingerprints)
      — `build.rs` + `include_str!`
- [x] `scripts/refresh-wappalyzer.sh` with license-capture +
      schema-drift sanity test
- [x] Stack Fingerprint passive check
- [x] Nuclei-Template passive check (matcher-only, per-template
      descriptors grouped by OWASP)
- [x] Tag-heuristic OWASP classifier

### OWASP Top 10 taxonomy

- [x] Move taxonomy out of Rust enums → `data/owasp/top10.yaml`
- [x] Shared data-driven classifier in `corvex-intel::owasp`
- [x] `OwaspCategory` newtype with `Axx()` constructors +
      taxonomy-resolved labels
- [x] Updated all 8 coded checks to use constructor form
- [x] `owasp_taxonomy_info` Tauri command
- [x] Taxonomy banner in Checks tab ("OWASP Top 10 v2025 ·
      released 2025 · owasp.org")
- [x] Category description tooltips on library group headers
- [x] Ship **OWASP Top 10 2025** as the active taxonomy
      (category remap complete, test expectations rewritten)

### Databases view

- [x] Fingerprints (Wappalyzer) tab with counts + top categories

### Help section

- [x] Proxy / Intercept / Replay / Checks — full section with
      11 sub-heads, every one with a worked example
- [x] Scenarios 11–16 — proxy-driven recipes (login capture,
      wire tampering, XSS hunt, SQLi probe, IDOR replay,
      passive header audit)
- [x] Scenario 25 — Banner-CVE cross-reference recipe
      (versioned banner → CVE list, CVSS + EPSS triage, false-
      positive guard against CDN banner spoofing)
- [x] Scenarios 26–27 — Boolean-blind SQLi confirmation
      playbook + Time-based blind SQLi oracle (two-shot
      confirmation, Replay validation, stall-time caveats)
- [x] Scenario 28 — Cloud-credential SSRF playbook
      (fetch-URL endpoints, AWS/GCP/Azure metadata leaks,
      manual IAM token escalation via Replay)
- [x] Scenario 29 — Hidden-parameter discovery playbook
      (class-based triage, pivot to SQLi/SSRF/XSS on the
      augmented parameter set, method-override CSRF bypass)
- [x] Scenario 30 — Active Nuclei template execution
      (path-specific templates, severity/KEV filter,
      INCLUDE_ALL widening, triage by CVE vs topic tag)
- [x] Glossary — 20 new terms under "Proxy & traffic
      interception" and "Checks & findings", plus 7 more for
      the Phase 3A+ checks (Banner CVE cross-reference,
      Boolean-blind SQLi, Time-based blind SQLi, SSRF, IMDS,
      Hidden-parameter discovery, Active Nuclei execution)

---

## ⏳ Pending — actionable, next up

### Help documentation
- [ ] **Known Limitations** section — update for proxy / checks /
      intercept behaviour (cert pinning, H2 latency, body size caps,
      response-phase intercept not wired)
- [ ] **Troubleshooting** section — add entries for CA trust failures
      per browser, intercept timeouts, `Drop` → 502 behaviour, empty
      Wappalyzer dataset, OWASP taxonomy swap side-effects
- [ ] **Datasets / Database management** section — document the
      Wappalyzer refresh script, Nuclei bundle refresh, OWASP
      taxonomy-update procedure (explicitly held out of the Proxy
      section per the user's direction)

### Proxy listener — functional gaps
- [x] Scope-rules UI in the Settings tab (backend accepts
      `scope_set`; no form / no chip list / no persistence)
- [x] Response-phase intercept handler in the Intercept tab
      (backend already pauses; UI only shows request-phase rows)
- [x] "Send to Fuzzer" cross-tool action on Traffic rows
- [x] WebSocket frame capture + side-panel viewer (upgrades
      pass through today; frames are not surfaced)
- [x] Large-body spill-to-file (512 KB inline cap → blob file;
      32 MB hard cap)
- [x] Retention policy — configurable max exchanges per session,
      ring-buffer eviction
- [x] HAR export of the exchange log
- [x] OpenAPI / Postman import as a seed for Checks targets

### Checks — coverage gaps
- [x] Banner-CVE cross-reference check (consumes Stack
      Fingerprint output + vulndb) — shipped as the
      `banner-cve` passive check, CVSS-mapped severity, EPSS
      evidence, curated Wappalyzer → CPE map in
      `corvex-core::sca::cpe_map::lookup_web_tech_cpe`.
- [x] Active Nuclei-template execution — shipped as the
      `nuclei-active` umbrella active check (see Phase 3A).
      Matcher-only passive path still runs alongside against
      already-captured traffic.
- [x] Blind SQLi (boolean + time) — shipped as
      `boolean-blind-sqli` and `time-based-sqli` (A05).
- [x] SSRF detector — shipped as `ssrf` (A10), marker-based
      oracle with AWS/GCP/Azure/DigitalOcean + loopback probes.
- [x] Hidden-parameter discovery — shipped as `hidden-params`
      (A05) with 13-group / ~220-name curated wordlist.
- [ ] Coded checks for OWASP A08 (Software/Data Integrity),
      A09 (Logging & Alerting), A10 (Mishandling of Exceptional
      Conditions) — SSRF (A10) now covers a slice, but coded
      checks for CORS misconfiguration, unsigned JWT, missing
      rate-limit signals, and mass assignment still rely on
      Nuclei classifier.
- [ ] Header-based SSRF (injecting into X-Forwarded-For,
      Referer, X-Original-URL) — today `ssrf` only probes
      query parameters with URL-shaped values.
- [ ] Blind SSRF via OOB interaction — needs Interactsh-
      equivalent server, deferred with the Nuclei OOB
      template bucket.

### Recon — passive + active DNS / subdomain discovery
- [x] `corvex-core::recon` module: trait `PassiveSource` + 3 keyless
      sources (crt.sh, AlienVault OTX, CertSpotter), async
      `run_recon` driver with event stream + cancellation
- [x] `corvex-core::dns` extensions: `detect_wildcard`,
      `brute_subdomains_filtered` (wildcard-aware), `lookup_host_addrs`
- [x] Embedded ~200-entry default subdomain wordlist
      (`corvex-core/data/subdomains.txt`)
- [x] Desktop: `recon_state.rs` registry + `recon_store.rs` SQLite
      persistence (`recon_runs` / `recon_findings` tables in shared
      `history.sqlite`) + `recon_cmd.rs` Tauri commands
- [x] UI: new top-level **Recon** sidebar view with Run / History
      tabs, live source-status chips, wildcard indicator, brute-force
      progress, subdomain + record grids
- [x] Cross-tool integrations: Send-to-Proxy-scope (bulk + per-row),
      Send-to-Checks (via new `proxy_seed_host` command),
      Send-to-Fuzzer (reuses FuzzerSeed lift path)
- [x] Help section: Recon sub-head, scenario 31, glossary entries for
      Recon and Wildcard DNS filtering

### Intel / datasets
- [x] Hidden-parameter wordlist — 13-group / ~220-name curated
      catalogue in `corvex-intel::hidden_params`, consumed by
      the `hidden-params` active check.
- [ ] Full SecLists / FuzzDB payload vendoring beyond the
      current hand-curated seed in `corvex-intel::payloads` and
      `corvex-intel::hidden_params`

### Desktop plumbing — cleanup
- [ ] Remove or surface `wappalyzer_summary`'s stale `upstream` /
      `upstream_ref` / `upstream_commit` / `refreshed_at` / `license`
      fields. The Databases view stopped rendering them — struct
      still carries them
- [ ] Remove `proxy_cmd::exchange_summary_payload` shim
      (`#[allow(dead_code)]`, unused now that the listener uses
      the broadcast channel directly)

### Verification
- [ ] Full `cargo tauri build` smoke: confirm the compile-time
      embedded Wappalyzer JSON + OWASP YAML actually end up in the
      bundled binary
- [ ] Real-browser end-to-end Phase 1 smoke (Firefox + Chromium
      through `127.0.0.1:8888` with the CA installed) — the
      automated integration tests cover the plumbing but not the
      browser trust path

---

## 🗂️ Deferred — intentionally out of scope for now

- [ ] CLI (`corvex` crate) proxy mode — explicitly deferred to
      post-v1; no API surface committed
- [ ] Stored XSS — canary-into-form-then-recrawl flow; still
      `status: "planned"` in FuzzingView.tsx
- [ ] DOM-based XSS — requires a headless browser; explicitly
      out of scope for the response-only XSS engine
- [ ] Subdomain-takeover detector — DNS enumeration exists
      in `corvex-plugins::dns_enum` but CNAME-fingerprint
      matching isn't wired
- [ ] Log4Shell runtime JNDI injection probe — needs OOB
      server to confirm; SCA path already detects vulnerable
      Log4j versions via the vulndb
- [ ] Interactsh / OOB-interaction Nuclei templates (~65) — parse-
      stubbed; need a real out-of-band server to fire. Blind
      SSRF confirmation also blocks on this.
- [ ] Raw HTTP request Nuclei templates — skipped at load
      (feature outside v1 engine)
- [ ] Non-HTTP-protocol Nuclei templates (network / dns / ssl /
      code / headless) — skipped at load
- [ ] Payload-file-reference Nuclei templates — skipped at load
- [ ] JARM hash catalog — ships with an illustrative placeholder
      dataset; real catalog is an operator workflow, not
      bundled data

---

## 📝 Notes on future taxonomy / dataset swaps

- **OWASP Top 10 refresh:** edit `crates/corvex-intel/data/owasp/top10.yaml`,
  bump `version` / `released`, re-run `cargo test -p corvex-intel`,
  `cargo build`. No Rust source changes needed.
- **Wappalyzer refresh:** run `scripts/refresh-wappalyzer.sh [ref]`
  from the repo root. Commits under
  `crates/corvex-intel/data/wappalyzer/`.
- **Nuclei bundle refresh:** Databases view → Nuclei templates tab →
  "Expand coverage" button downloads the latest tier-2 extras; or use
  the underlying `nuclei_extras_download` command.
