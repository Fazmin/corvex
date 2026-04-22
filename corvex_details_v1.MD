# Corvex Desktop — Comprehensive Product Overview (v1)

> A single-binary, cross-platform vulnerability discovery and web-application
> assessment workbench, built in Rust with a Tauri v2 front-end.
>
> This document explains what the desktop app is, what it does, which
> security-engineering workflows it accelerates, and how every view in the
> UI maps to a real engine in the codebase. It is intended as a briefing
> document you can hand to a colleague, a manager, or a prospective user.

---

## 1. What Corvex is, in one paragraph

**Corvex Desktop** (`corvex-rust`) is a local, offline-capable security
assessment GUI that bundles **eight specialised engines** into a single
installable application:

1. A **web signature scanner** (Nikto-class, ~7,200 tests).
2. An **active fuzzer** for XSS, SSTI, CRLF, XXE, LFI, command injection,
   open redirect, and CVE chains.
3. A full **SQL-injection engine** (SQLMap-class: 5 techniques, 8 DBMS
   backends, ~50 WAF-bypass tamper modules, enumeration + exploitation).
4. A **Software Composition Analysis (SCA)** engine backed by a local
   NVD + EPSS mirror with binary and SBOM analysis.
5. A **service probing** engine (Nmap-class service detection + JARM TLS
   fingerprinting).
6. An **intercepting HTTP/HTTPS proxy** with its own Certificate
   Authority, per-session SQLite history, request/response interception,
   and replay (Burp/mitmproxy-class workflow).
7. A **Checks engine** that continuously evaluates proxy traffic against
   OWASP Top-10-taxonomy passive/active checks.
8. A **Nuclei template runner** for community-maintained YAML detection
   rules, with bundled + on-demand template trees.

Everything runs locally. The binary ships the signature databases,
Wappalyzer-compatible fingerprints, a curated Nuclei template set, the
OWASP taxonomy, and a private CA generator. No SaaS, no cloud, no
telemetry.

The GUI is a Tauri v2 shell (Rust core + React/TypeScript front-end). The
same Rust engines power both the headless CLI (`corvex`) and the desktop
binary (`corvex-desktop`) — the UI is a thin command surface, not a
re-implementation.

---

## 2. Who it's for

| Role | Why it helps |
| --- | --- |
| **Penetration testers** | Everything a baseline web-app engagement needs in one window: recon (DNS/probe), discovery (crawler + Nuclei + signatures), active testing (SQLi, XSS, CMDi, LFI, XXE, SSTI), and an intercepting proxy with replay — without juggling Nikto, Nmap, SQLMap, Nuclei, Burp, and mitmproxy. |
| **Application security engineers** | SCA view analyses dependency manifests, binaries, and SBOMs against a local NVD+EPSS mirror. Proxy + Checks give continuous passive OWASP findings while a dev team exercises the app. |
| **Red teamers** | Port scan + service fingerprint + JARM per target, fuzz APIs under scope, use intercept/replay for tailored exploits. Runs air-gapped. |
| **Blue teams / detection engineers** | Proxy session DB plus exchange replay make it easy to reproduce attack traffic for signature authoring and detection tuning. |
| **Security students / instructors** | Every view includes built-in technique documentation (SQLi techniques, tamper modules, DBMS specifics, JARM, OWASP categories, Nuclei template reference) — the app doubles as reading material. |
| **Compliance / SBOM owners** | Generate CycloneDX or SPDX SBOMs from source trees, import pre-existing SBOMs, enrich with NVD/EPSS and fix availability. |

---

## 3. Architecture at a glance

```
+-----------------------------------------------------------+
|                   corvex-desktop (Tauri v2)               |
|                                                           |
|   +-------------------------------------------+           |
|   |   React / TypeScript UI (ui/src)          |           |
|   |   ScanForm  Sidebar  FindingsTable  ...   |           |
|   +----------------------+--------------------+           |
|                          | Tauri invoke / events          |
|                          v                                |
|   +-------------------------------------------+           |
|   |   Rust command surface (src/*.rs)         |           |
|   |   commands.rs   proxy_cmd.rs   history.rs |           |
|   |   check_bridge  event_sink   params       |           |
|   +----+--------+--------+--------+--------+--+           |
|        |        |        |        |        |             |
|        v        v        v        v        v             |
|   corvex-  corvex-  corvex-   corvex-  corvex-           |
|   core     plugins  nuclei    sonar    proxy             |
|                                                           |
|   corvex-checks   corvex-intel   (shared crates)         |
|                                                           |
+-----------------------------------------------------------+
          |                 |                 |
          v                 v                 v
    history.sqlite    proxy/ca/*.pem    nuclei-templates/
    (app_data_dir)    (app_data_dir)    (bundled + cache)
```

**Key properties:**

- Rust async runtime (`tokio`) handles all engine I/O.
- Tauri emits named events (`scan://{id}/finding`, `proxy://exchange-new`,
  `probe://{id}/open-port`, `log://line`) so the UI updates in real time
  with zero polling on hot paths.
- A single SQLite file (`history.sqlite`) stores both the scan-run
  history and proxy exchanges + findings. WAL mode lets the scanner and
  proxy share the file across connections.
- The Certificate Authority for HTTPS MITM is generated lazily in
  `<app_data_dir>/proxy/ca/` on first proxy start.
- The window is a custom-chrome Tauri window (no native title bar) with
  a collapsible left rail and a resizable findings pane; the experience
  is identical on Windows, macOS, and Linux.

---

## 4. Feature map — one paragraph per view

### 4.1 Dashboard (signature scanner + active fuzzer)

The landing screen. The `ScanForm` exposes every knob a typical web
assessment needs: host/URL target, port, SSL on/off, IPv4/IPv6
preference, virtual host, custom headers, evasion tricks (9 categories:
random URL encoding, directory self-reference, premature URL ending,
fake parameters, TAB-as-spaces, case-manipulation, Windows separators,
session-splicing), tuning filters, plugin selector, concurrency, active
fuzzing toggles (crawl depth, max URLs, scope, exclusion regex), 404
override, user-agent, proxy, timeout/pause/max-time, and file output
format. Starting a scan spawns a Rust task that streams `finding`,
`host-start`, `host-end`, and `summary` events through the Tauri event
bus into a live `FindingsTable`, a `StatsBar` (requests, findings,
errors, rate, progress), a `SeverityBreakdown` chip strip, and a
resizable `LogPanel` fed by the global `tracing` subscriber. A running
scan shows a pulsing indicator in the sidebar and a dashboard-level
ScanIndicator with a cancel button. Finished scans are persisted to the
history DB.

### 4.2 History

SQLite-backed scan log at `app_data_dir/history.sqlite`. Shows every
scan's host, parameters (as JSON), start/end times, status
(`running/done/cancelled/error`), total requests, findings, and errors.
Users can re-run any prior scan with a single click (the saved JSON
params re-populate `ScanForm`), delete individual entries, or clear
history.

### 4.3 Plugins

Read-only listing of the 26 compile-time scan plugins shipped in this
build. Each row shows the plugin name, hook types (`start`, `recon`,
`scan`, `prefetch`, `postfetch`, `active`), description, full name, and
priority weight. Used for "what exactly runs during a default scan?"
briefings.

### 4.4 Probing (service fingerprinting)

A dedicated Nmap-class surface with two scan modes (`rapid` — TCP
connect sweep; `deep` — protocol-aware probes with fingerprint
matching), a ports expression box (`1-1000`, `80,443,8080-8090`, etc.),
JARM toggle, and host concurrency. Targets accept IPv4/IPv6 literals,
hostnames (DNS-resolved), CIDR blocks (`/8` safely capped at 65,536
hosts), dash-ranges (`10.0.0.5-10.0.0.12`), short-octet ranges
(`192.168.1.10-12`), and comma-separated lists.

Each open port emits a `probe://{id}/open-port` event carrying service
name, product, vendor, version, info banner, CPE list, TLS flag, JARM
hash, and raw banner. The view has tabs for **Run** (live progress),
**Configure** (persisted defaults), **Scan modes** (what Rapid vs Deep
actually do), **Probe families** (scripted probes, static probes,
fingerprint sets), **Datasets** (bundled + user-supplied probe files
with counts), **JARM** (TLS fingerprint explainer + hash lookup), and
**Directive format** (probe file syntax reference). Extra probe files
are merged into the live probe DB on the fly.

### 4.5 Fuzzing (active injection)

Module inventory for the active fuzzing engine with 16 detectors:

| Category | Modules |
| --- | --- |
| Injection (ready) | `xss_reflected`, `sqli_error`, `sqli_boolean`, `sqli_time`, `sqli_union`, `sqli_stacked`, `sqli_enumerate`, `sqli_exploit`, `lfi_active`, `cmd_injection`, `crlf`, `open_redirect`, `xxe`, `ssti` |
| Injection (planned) | `xss_stored`, `ssrf`, `file_upload` |
| Fingerprint (planned) | `cms`, `tech`, `subdomain_takeover` |
| CVE chains | `log4shell` (planned), `spring4shell` (ready), `nuclei` (ready) |

Shipped reference tables inside the view cover: the five SQLi techniques
(Error / Boolean / Time / UNION / Stacked) with per-technique request
budgets, the ~50 tamper modules grouped by category
(space-replacement, encoding, keyword-obfuscation, comparison/logic,
injection/advanced), DBMS-specific fingerprint rules for 8 engines, and
post-detection enumeration targets (databases, tables, columns, users,
password hashes, privileges). The `ActiveFuzzRunner` sub-panel lets the
user launch an active scan directly from this view with the right
`sqli_level`, `sqli_risk`, `sqli_techniques` (BEUST), `sqli_dbms`,
`sqli_time_delay`, `tamper` chain, and `sqli_enumerate` list.

### 4.6 Intercept (proxy + replay + checks)

Five sub-tabs:

- **Traffic** — Live list of HTTP/HTTPS exchanges captured by the
  embedded MITM proxy. Each row shows method, scheme, host:port, path,
  status, size, duration, scope decision (`in`/`out`/`excluded`),
  origin (browser, replay, check), and tags. Clicking opens
  request/response headers and a base64 body viewer (so binary bodies
  don't explode the UI).
- **Intercept** — Queue of requests/responses paused by the user's
  intercept mode (`off` / `request` / `response` / `both`). Each
  pending item can be **Forwarded**, **Edited and forwarded** (raw
  bytes replaced), or **Dropped**. Subscribes to
  `proxy://intercept-pending` events for zero-poll updates.
- **Replay** — Pick a captured exchange, optionally mutate its raw
  request bytes, and re-send through the same upstream client. The
  replayed exchange is written back to the session DB under origin
  `Replay{parent}` so replays stack alongside the original request in
  Traffic.
- **Checks** — Library of passive + active checks grouped by OWASP Top
  10 category (version, release date, and description sourced from the
  active `top10.yaml` taxonomy). The user selects one or more exchanges
  + one or more active check IDs and clicks Run; findings stream in
  through `proxy://scan-finding` events and get persisted in the shared
  SQLite DB. Passive checks run automatically on every in-scope
  exchange via `check_bridge.rs`.
- **Settings** — Listen address (default `127.0.0.1:8888`), session
  start/stop, live status (session ID, exchanges captured, CA ready),
  and a one-click **Export CA as PEM** button so users can trust the
  generated CA in Firefox / Chrome / the OS root store.

### 4.7 Databases (embedded datasets)

Six tabs inspecting what ships inside the binary:

- **Web signatures** — `db_tests` (7,236), `db_outdated` (1,257),
  `db_favicon` (362), `db_server_msgs` (260), `db_realms` (170),
  `db_variables`, `db_content_search`, `db_headers_common`,
  `db_headers_suggested`, `db_multiple_index`, `db_options`,
  `db_useragents`, `db_dictionary` (1,825), `db_404_strings`.
- **Probing** — Scripted probes (SSH, HTTP, TLS, SMTP, FTP, MySQL, …),
  static banner probes, fingerprint sets, and JARM-known entries.
  Extra probe files configured in Settings are counted here.
- **SCA / VulnDB** — Row counts for CVEs, CPE matches, EPSS scores, fix
  availability. Buttons to run an NVD update (`daily` / `full`) via
  `vulndb_update`. Honors `NVD_API_KEY` for higher rate limits.
- **Fuzzing** — Re-surfaces the FuzzingView reference tables
  (techniques, tampers, DBMS, enumeration targets) for quick lookup.
- **Nuclei templates** — Supported/skipped counts, severity and tag
  breakdowns, Tier-1 bundled root + Tier-2 extras cache path, a button
  to **download the full ProjectDiscovery `v10.4.2` HTTP template tree**
  into the user data dir (only `http/` is unpacked to keep the cache
  lean), and a **remove** button. Template bundle tag and commit SHA
  are shown for provenance.
- **Fingerprints (Wappalyzer)** — Category counts for the vendored
  Wappalyzer-compatible dataset. A compile-time seed is always present
  so the stack-fingerprint check still works even before the upstream
  dataset is refreshed.

### 4.8 SCA (Software Composition Analysis)

Four tabs:

- **Dependency analysis** — Point it at a directory of manifests
  (`Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`,
  `pom.xml`, `composer.json`, `Gemfile`, `pyproject.toml`,
  `packages.lock.json`, …) or at an existing SBOM (CycloneDX
  JSON/XML, SPDX JSON/tag-value). Emits findings tied to a CVE, CVSS,
  EPSS score/percentile, fix version, and affected component.
- **Binary analysis** — ~50 static/CVE detectors run against compiled
  executables. Supports recursive directory scanning and archive
  extraction.
- **Results** — Unified findings list with severity filters, EPSS
  threshold slider (0.0–1.0), and optional fix-version output.
- **VulnDB** — Summary of CVE / CPE-match / EPSS / fix counts, last
  NVD and EPSS update timestamps, and an update button.

### 4.9 Settings

- **Appearance** — `system` / `light` / `dark` theme preference
  persisted in localStorage.
- **Typography** — Four font sizes (`small` / `medium` / `large` /
  `xlarge`) with a live preview.
- **Scanner defaults** — Probing defaults (scan mode, ports range, JARM)
  and extra probe files merged into every probe run.
- **Onboarding** — Reset the first-run onboarding tour.

### 4.10 Help

Built-in manual: getting-started, every view explained, proxy workflow
(CA trust, scoping, intercept verdicts, replay), service-probing
reference, scenario recipes, a ScanForm field-by-field reference,
interface tips, data/storage locations, the full bundled Nuclei
template catalogue (fetched via `nuclei_template_list`), a glossary,
known limitations, and troubleshooting. Searchable table of contents
with scroll-spy highlighting.

---

## 5. Backend surface (Tauri commands)

Every user action in the UI funnels through one of the following
commands (defined in `src/commands.rs` and `src/proxy_cmd.rs`). The
rest is rendering.

| Command | What it does |
| --- | --- |
| `list_plugins` | Enumerate compile-time plugin registry. |
| `db_summary` | Row counts for every embedded web-signature DB. |
| `version_info` | Product name + semver. |
| `scan_start` | Spawn a scan (signature + optional active fuzz + SCA + portscan). Returns a UUID the UI subscribes to for events. |
| `scan_cancel` | Cooperatively cancel a running scan via a `CancellationToken`. |
| `scan_stats` | Snapshot counts from the scan's `GlobalState`. |
| `history_list` / `history_clear` / `history_delete` | SQLite history CRUD. |
| `vulndb_summary` / `vulndb_update` | NVD+EPSS vulnerability DB inspector + refresher. |
| `sonar_summary` | Inventory of scripted/static probes + fingerprint sets, with user-supplied extra files merged in. |
| `nuclei_summary` / `nuclei_template_list` / `nuclei_extras_download` / `nuclei_extras_remove` | Nuclei bundle inspector + tier-2 cache management. |
| `wappalyzer_summary` | Fingerprint dataset (embedded + seed). |
| `jarm_lookup` | Decompose a JARM hash into cipher/version + extensions digest and look up known matches. |
| `probe_start` / `probe_cancel` | Standalone service probing (target expansion, per-host concurrency, live events). |
| `proxy_start` / `proxy_stop` / `proxy_status` / `proxy_export_ca_pem` | Proxy session lifecycle + CA export. |
| `exchanges_list` / `exchange_get` | Query the per-session exchange store. |
| `intercept_set_mode` / `intercept_get_mode` / `intercept_pending_list` / `intercept_resolve` / `intercept_drop_all` | Intercept queue control. |
| `replay_send` | Re-send a stored request with optional raw-byte edit. |
| `checks_list` / `findings_for_exchange` / `findings_for_session` / `checks_run` | Checks engine descriptors, per-exchange and per-session findings, on-demand active check runs. |
| `owasp_taxonomy_info` | Version, release, source, and full category list for the active `top10.yaml`. |

---

## 6. Event bus (what the UI listens to)

- `scan://{id}/host-start` / `host-end` — each target transition.
- `scan://{id}/finding` — each new finding (streamed, not batched).
- `scan://{id}/summary` — periodic aggregate.
- `scan://{id}/done` — terminal status (`done` / `cancelled` / `error`).
- `probe://{id}/host-start` / `host-end` / `open-port` / `summary` / `error`.
- `proxy://exchange-new` — every captured HTTP exchange (summary).
- `proxy://intercept-pending` — new item parked on the intercept queue.
- `proxy://scan-finding` — passive or active Check finding for a captured exchange.
- `log://line` — every `tracing` event the engine emits (level, target, message).

This push model is why the LogPanel, StatsBar, FindingsTable, Traffic
list, Intercept queue, and Probe runner stay responsive under heavy
load — the front-end isn't polling anything.

---

## 7. On-disk footprint

| Path (platform-resolved via `app_data_dir`) | Contents |
| --- | --- |
| `history.sqlite` | Scan history table + proxy sessions, exchanges, findings. WAL mode so scanner and proxy share it safely. |
| `proxy/ca/ca.cert.pem` + `proxy/ca/ca.key.pem` | Locally-generated Certificate Authority for HTTPS MITM. Regenerated on first proxy start if missing. |
| `corvex/nuclei-templates/<tag>/` | Tier-2 Nuclei template cache (only `http/` is unpacked from the GitHub tarball). |
| Bundled in binary | Web-signature DBs, Nuclei tier-1 curated templates, Wappalyzer seed + dataset, JARM known hashes, default config, OWASP `top10.yaml`. |

Nothing is written outside the user's data dir. No registry entries. No
network calls unless the user explicitly clicks **Update VulnDB** or
**Download extras**.

---

## 8. Concrete workflows Corvex accelerates

### 8.1 "I need a baseline scan of a new web app."

Dashboard → enter host → Start. Signature engine runs all 26 plugins
against the target, findings stream in severity-ranked in real time,
HTML report is optional. One click.

### 8.2 "Is this app's dependency tree vulnerable?"

SCA → Dependency analysis → point at the project folder → Run. Findings
come back enriched with CVE, CVSS, EPSS, and (when published) a
fix-version — perfect for a ticket that tells a developer "upgrade
`lodash@4.17.15` to `4.17.21`, CVE-2020-8203, EPSS 0.91".

### 8.3 "Reproduce and iterate on an attack observed in the wild."

Intercept → Start proxy (port 8888) → export CA → trust in browser →
exercise the app → find the interesting request in Traffic → Replay →
edit the body → send. Passive checks flag OWASP categories as you go;
active checks (SQLi, header issues, auth, injections) run on demand
against the selected exchange.

### 8.4 "What exposed services does this subnet actually run?"

Probing → targets `10.0.0.0/24` → Deep mode + JARM → Run. Stream of
open ports with product, version, CPE, and TLS JARM hash. Useful for
asset discovery before a pentest kickoff.

### 8.5 "A new CVE dropped — am I exposed?"

SCA → VulnDB → Update (daily). Then re-run dependency or binary
analysis. The local NVD mirror means the whole flow works offline after
the initial update, and EPSS lets you triage which CVEs actually have
real-world exploitation pressure.

### 8.6 "I want to fuzz the login and search endpoints without writing
a single SQLMap command."

Dashboard → enable Active → set scope/depth/max URLs → start. Or go to
Fuzzing → configure SQLi level/risk/technique/tamper-chain → Run. All
eight DBMS backends, five techniques, ~50 tampers, enumeration and
risk-3 exploitation are gated behind the same UI.

### 8.7 "Make the proxy scan my Burp-style workflow for OWASP findings."

Intercept → Start → Checks tab → review the built-in OWASP Top 10
library → passive checks run automatically on every exchange → select
a suspicious exchange → run the specific active checks you care about
(e.g. `redirect-*`, `cors-*`, `headers-*`, `authn-*`). Every finding is
persisted and re-loadable next session.

---

## 9. Why it's valuable to security professionals

1. **One binary, no plugin hunt.** Nikto + Nmap-service + SQLMap +
   Nuclei + a mini-Burp + an SCA scanner would normally be 5–7 tools
   with 5–7 install paths, 5–7 update flows, and different output
   formats. Corvex collapses that into a single Rust binary with a
   consistent UI and a shared SQLite history/findings store.

2. **Runs offline.** The signature DB, Nuclei tier-1 templates,
   Wappalyzer seed, OWASP taxonomy, and probe data are all compiled
   into the executable. The NVD/EPSS mirror is local. The proxy's CA is
   self-generated. Good for classified/air-gapped environments.

3. **Memory-safe + high-concurrency.** `tokio`-based async I/O, raw
   HTTP/1.x framing, OpenSSL with SNI / TLS 1.3 / ALPN, bounded
   `Semaphore`s for host + request concurrency, and cooperative
   cancellation. Long scans don't leak resources and can always be
   stopped mid-flight.

4. **Live telemetry instead of wait-and-hope.** Every subsystem emits
   events: scan findings, proxy exchanges, probe results, and tracing
   logs. The UI reflects engine state within milliseconds of each
   underlying event. Great for demos, triage, and teaching.

5. **Provenance built in.** Nuclei templates preserve original author
   attribution. The Wappalyzer dataset includes upstream license info.
   The SCA VulnDB records last NVD/EPSS update timestamps. Every scan
   run is saved as JSON params you can audit or re-use.

6. **Fully scriptable surface.** Every UI action maps to a documented
   Tauri command and a typed event; the same engines have a matching
   CLI (`corvex`) so CI pipelines, runbooks, and GUI sessions share one
   source of truth.

7. **Teachable.** The Help view, the Fuzzing reference tables, the
   Probing directive format docs, the OWASP category descriptions, and
   the bundled Nuclei catalogue mean a junior engineer can learn the
   "why" without leaving the tool.

---

## 10. Known scope / limitations (v1)

- The GUI exposes *most* but not *all* CLI flags — VEX/triage, report
  merging/diffing, and OpenAPI ingestion are CLI-only today.
- Nuclei tier-2 downloads only `http/` (the other protocol trees —
  `network/`, `dns/`, `ssl/`, … — are not runnable in v1 and would just
  inflate cache).
- XSS is reflected-only in v1; DOM-based and stored XSS are planned.
- SSRF, file-upload, CMS fingerprint, tech fingerprint, subdomain
  takeover, and Log4Shell detectors are declared ready-to-ship modules
  marked **planned** in `FuzzingView.tsx` — they already have UI
  surfaces but are not yet wired to runnable detectors.
- CIDR expansion is IPv4-only in v1 (IPv6 literals work as single
  targets).
- The Checks engine runs against live proxy exchanges; running it
  against stored HAR/history requires replay.

---

## 11. Quick reference — where things live in the repo

```
crates/corvex-desktop/
  src/
    main.rs           Tauri bootstrap, log + proxy + history setup
    commands.rs       Scan/probe/db/nuclei/wappalyzer/jarm commands
    proxy_cmd.rs      Proxy + intercept + replay + checks commands
    check_bridge.rs   Subscribes to proxy exchanges → runs passive checks
    event_sink.rs     ReportSink that emits Tauri events per finding
    history.rs        SQLite scan-history DB
    log_bridge.rs     Pipes `tracing` events into the UI log panel
    params.rs         JSON shape for scan_start → corvex-core::cli::Cli
    probe_state.rs    In-memory registry of running probe UUIDs
    scan_state.rs     In-memory registry of running scan UUIDs
  ui/src/
    App.tsx           Root layout, view router, event wiring
    api.ts            Typed wrappers over invoke + listen
    components/       One file per view: Dashboard, ProxyView,
                      FuzzingView, ScaView, ProbingView,
                      DatabasesView, HistoryView, HelpView,
                      PluginsView, SettingsView, plus small widgets
                      (FindingsTable, StatsBar, LogPanel,
                      SeverityBreakdown, Sidebar, Toast,
                      OnboardingTour, etc.)
  tauri.conf.json     Tauri window + bundle + resource config
```

Shared engines under `crates/`:

| Crate | Purpose |
| --- | --- |
| `corvex-core` | HTTP client, config, scan runner, plugin registry, DBs, tuning, evasion, scope, CLI shape, VulnDB, port-scan, fuzz runner, SCA |
| `corvex-plugins` | The 26 compile-time scan plugins + report sinks |
| `corvex-nuclei` | YAML template parser, store, runner |
| `corvex-sonar` | Service probing engine (scripted + static probes, fingerprints, JARM) |
| `corvex-proxy` | MITM proxy, CA authority, exchange store, intercept queue, replay |
| `corvex-checks` | OWASP-taxonomy passive + active check registry |
| `corvex-intel` | Wappalyzer dataset + OWASP taxonomy loader |

---

## 12. TL;DR pitch

> Corvex Desktop gives a security engineer a Nikto-class signature
> scanner, an SQLMap-class SQLi engine, a Nuclei template runner, an
> Nmap-class service prober, a mini-Burp intercepting proxy with
> replay, an OWASP-aligned passive/active Checks engine, and an SBOM +
> binary + dependency vulnerability workbench — all in one Tauri
> binary, backed by a local NVD+EPSS mirror and a local SQLite history
> store, with live streaming UI, teachable in-app documentation, and
> zero required network access beyond the handful of updates the user
> initiates explicitly.
