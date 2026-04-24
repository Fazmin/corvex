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
   Authority, per-session SQLite history, request *and* response
   interception, WebSocket frame capture, scope rules, retention
   policy, HAR export, OpenAPI / Postman spec import, and full replay
   (Burp/mitmproxy-class workflow).
7. A **Checks engine** that continuously evaluates proxy traffic
   against the OWASP Top 10 v2025 taxonomy with 6 passive and 7 coded
   active checks (plus an umbrella active-Nuclei runner and per-template
   rules), writing findings to the shared SQLite store.
8. A **Nuclei template runner** for community-maintained YAML detection
   rules, with bundled + on-demand template trees, surfaced as passive
   matcher-only checks against captured traffic *and* as an active
   umbrella check (`nuclei-active`) that fires eligible HTTP templates
   against a target.

Everything runs locally. The binary ships the signature databases,
Wappalyzer-compatible fingerprints, a curated Nuclei template set, the
OWASP Top 10 v2025 taxonomy, a 13-group / ~220-name hidden-parameter
wordlist, a curated Wappalyzer → CPE map for banner-CVE lookups, and a
private CA generator. No SaaS, no cloud, no telemetry.

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

Five sub-tabs, wrapped in a toolbar that exposes the listener lifecycle
(Start / Stop, listen address, running badge, CA-ready badge), a
session-level **Export HAR** button, and an **Import spec** button that
seeds the active session from an OpenAPI 3 JSON or Postman v2.1
collection.

- **Traffic** — Live list of HTTP/HTTPS exchanges captured by the
  embedded MITM proxy. Each row shows method, scheme, host:port, path,
  status, size, duration, scope decision (`in`/`out`/`excluded`),
  origin (browser, replay, check, imported), and tags (`websocket`,
  `ws-extension`, `body-truncated`, …). Clicking a row expands an
  in-place detail strip with IDs, req/res size, MIME, scope chip, and
  three cross-tool actions — **Send to Replay**, **Send to Checks**,
  and **Send to Fuzzer** (seeds the Active Fuzzing form with the
  captured URL and opens the Fuzzing view). WebSocket upgrades show a
  `ws` badge; expanding the row reveals a live frame list (opcode,
  direction, FIN flag, sequence, text/binary preview) fed by a
  `proxy://ws-frame` broadcast. Request / response bodies follow a
  two-tier cap: 512 KB inline in SQLite, anything bigger spills to a
  blob file; 32 MB hard cap per side triggers a `body-truncated` tag.
- **Intercept** — Queue of requests *and* responses paused by the
  user's intercept mode (`off` / `request` / `response` / `both`).
  Each pending item can be **Forwarded**, **Edited and forwarded**
  (raw bytes replaced), or **Dropped**. Subscribes to
  `proxy://intercept-pending` events for zero-poll updates, with a
  5-minute auto-forward safety timeout so a forgotten pause can't hang
  the browser.
- **Replay** — Pick a captured exchange, optionally mutate its raw
  request bytes, and re-send through the same upstream client. The
  replayed exchange is written back to the session DB under origin
  `Replay{parent}` so replays stack alongside the original request in
  Traffic.
- **Checks** — Library of passive + active checks grouped by OWASP
  Top 10 v2025 category (version, release date, and description
  sourced from the active `top10.yaml` taxonomy; a banner at the top
  surfaces version + upstream link). The current build ships **6
  passive checks** (Security Headers, Verbose Errors, Version
  Disclosure, Insecure Cookies, Stack Fingerprint, Banner CVE
  Cross-Reference), **7 coded active checks** (Reflected XSS, Error-
  based SQLi, Boolean-blind SQLi, Time-based SQLi, Open Redirect,
  SSRF, Hidden-Parameter Discovery), an **active Nuclei umbrella**
  (`nuclei-active`) that drives the bundled HTTP template store against
  a chosen target, and **per-template rows** for every supported
  Nuclei template so users can enable / disable individual rules. The
  library supports free-text search, "enabled only" filter, and OWASP-
  category descriptions in header tooltips. The user picks one or more
  exchanges (via *Send to Checks* on Traffic rows) plus one or more
  active check IDs and clicks Run; findings stream in through
  `proxy://scan-finding` events and get persisted in the shared SQLite
  DB. Passive checks run automatically on every in-scope exchange via
  `check_bridge.rs`.
- **Settings** — Seven-section guided setup:
  1. **Overview** — ordered checklist (CA → Browser → Verify) with
     deep links to each sub-section.
  2. **Certificate authority** — one-click **Export CA as PEM**
     button, path of the on-disk CA, per-OS install commands
     (macOS `security add-trusted-cert`, Linux `update-ca-trust`,
     Windows `certutil -addstore`) so users can trust the
     auto-generated CA in the system root store.
  3. **Browser setup** — Firefox, Chrome/Edge, and Safari walkthroughs
     with proxy-extension hints (FoxyProxy, SwitchyOmega).
  4. **Scope rules** — persisted include / exclude lists. Each rule
     is `{ host, path_regex?, port? }`; host supports exact and
     `*.example.com` wildcard, path is a Rust regex evaluated at
     capture time, port is optional. Empty include = all in-scope;
     exclude always wins. Stored in the proxy DB via `scope_set` /
     `scope_get` and hydrated into the listener at startup.
  5. **Retention** — configurable ring buffer `max_exchanges_per_session`
     (presets 1k / 5k / 20k / 100k / unlimited, default 5,000). On
     every ~250 ms flush the writer evicts oldest rows plus their
     dependent WebSocket frames and scan findings; the cap is
     per-session (each Start / Stop cycle gets its own budget).
     Persisted via `retention_set` / `retention_get`.
  6. **Verify** — smoke-test checklist (open an HTTP then an HTTPS
     page, confirm Traffic rows appear, body visible).
  7. **Troubleshooting** — common failure modes (CA not trusted,
     HSTS pins, certificate pinning, proxy bypassed).

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
| `scope_get` / `scope_set` | Persisted include / exclude scope rule list (host, path regex, port). Path regexes are validated on save. |
| `retention_get` / `retention_set` | Ring-buffer `max_exchanges_per_session` policy; 0 disables eviction, values over 1,000,000 are clamped. |
| `proxy_export_har` | Stream the active session's captured exchanges out as a HAR 1.2 file (non-blocking; runs on the blocking pool so capture keeps going). |
| `proxy_import_spec` | Parse an OpenAPI 3 JSON or Postman v2.1 collection and seed the active session with one `Imported` exchange per endpoint so Checks can target never-visited routes. Reports `{imported, skipped, format}`. |
| `ws_frames_for_exchange` / `ws_frame_count` | Per-exchange WebSocket frame listing + count. Used by the traffic detail panel's frame viewer. |
| `exchanges_list` / `exchange_get` | Query the per-session exchange store. `exchange_get` returns a 1 MB-per-side preview plus full req/res size so the UI can show a "truncated" indicator. |
| `intercept_set_mode` / `intercept_get_mode` / `intercept_pending_list` / `intercept_resolve` / `intercept_drop_all` | Intercept queue control (applies to both request and response phases). |
| `replay_send` | Re-send a stored request with optional raw-byte edit. The result is persisted as a new exchange under origin `Replay{parent}` and broadcast. |
| `checks_list` / `findings_for_exchange` / `findings_for_session` / `checks_run` | Checks engine descriptors, per-exchange and per-session findings, on-demand active check runs. Descriptor rows carry their resolved OWASP category label + description from the active `top10.yaml`. |
| `owasp_taxonomy_info` | Version, release, source, and full category list for the active `top10.yaml`. |

---

## 6. Event bus (what the UI listens to)

- `scan://{id}/host-start` / `host-end` — each target transition.
- `scan://{id}/finding` — each new finding (streamed, not batched).
- `scan://{id}/summary` — periodic aggregate.
- `scan://{id}/done` — terminal status (`done` / `cancelled` / `error`).
- `probe://{id}/host-start` / `host-end` / `open-port` / `summary` / `error`.
- `proxy://exchange-new` — every captured HTTP exchange (summary).
- `proxy://ws-frame` — every captured WebSocket frame (exchange id, sequence, direction, opcode, FIN flag, base64 payload).
- `proxy://intercept-pending` — new item parked on the intercept queue (request or response phase).
- `proxy://scan-finding` — passive or active Check finding for a captured exchange.
- `log://line` — every `tracing` event the engine emits (level, target, message).

This push model is why the LogPanel, StatsBar, FindingsTable, Traffic
list, Intercept queue, and Probe runner stay responsive under heavy
load — the front-end isn't polling anything.

---

## 7. On-disk footprint

| Path (platform-resolved via `app_data_dir`) | Contents |
| --- | --- |
| `history.sqlite` | Scan history table + proxy sessions, exchanges, WebSocket frames, scope rules, retention setting, key/value settings, findings. WAL mode so scanner and proxy share it safely. |
| `proxy/ca/ca.cert.pem` + `proxy/ca/ca.key.pem` | Locally-generated Certificate Authority for HTTPS MITM. Regenerated on first proxy start if missing. |
| `proxy/bodies/<exchange-id>.{req,res}.bin` | Large request / response bodies that exceed the 512 KB inline cap are spilled here (up to the 32 MB per-side hard cap). Evicted alongside the parent exchange when retention trims. |
| `corvex/nuclei-templates/<tag>/` | Tier-2 Nuclei template cache (only `http/` is unpacked from the GitHub tarball). |
| Bundled in binary | Web-signature DBs, Nuclei tier-1 curated templates, Wappalyzer seed + dataset, JARM known hashes, default config, OWASP `top10.yaml`, hidden-parameter wordlist, Wappalyzer → CPE map. |

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

Intercept → Start → Checks tab → review the built-in OWASP Top 10 v2025
library → passive checks (Security Headers, Verbose Errors, Version
Disclosure, Insecure Cookies, Stack Fingerprint, Banner CVE) run
automatically on every in-scope exchange → select a suspicious
exchange → run the specific active checks you care about (Reflected
XSS, Error-based SQLi, Boolean-blind SQLi, Time-based SQLi, Open
Redirect, SSRF, Hidden-Parameter Discovery, `nuclei-active`). Every
finding is persisted and re-loadable next session.

### 8.8 "Drive the Checks engine against an API I haven't clicked through yet."

Intercept → Start → **Import spec** → pick an OpenAPI 3 JSON or Postman
v2.1 collection → every endpoint lands in Traffic as an
`origin = Imported` row. Select rows → Send to Checks → Run the active
checks — the engine mutates parameters from the spec just as if you'd
recorded them live. Pair with **Scope rules** to exclude auth / logout
paths so the run doesn't nuke your session cookie.

### 8.9 "Archive a session for offline review or handoff."

Intercept → (session running or finished) → **Export HAR** → file
picker → HAR 1.2 file with every captured request / response (bodies
base64-encoded) is written. The export streams through the blocking
pool so capture keeps going on a live session. Counterpart for blue
teams: feed the HAR into your SIEM or detection-rule tester.

### 8.10 "Is this banner actually exploitable?"

Keep the proxy running while you browse → the **Stack Fingerprint**
passive check tags each response with detected products / versions
(Wappalyzer-schema dataset) → **Banner CVE** then queries the local
NVD mirror per versioned banner, produces one finding per CVE with
CVSS-mapped severity, adds EPSS score + percentile as evidence, and
caps at 25 findings per exchange to avoid flooding noisy pages. No
vulndb = check silently disabled; run **Update VulnDB** once from the
Databases view to light it up.

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

- The GUI exposes *most* but not *all* CLI flags — VEX/triage and
  report merging/diffing are CLI-only today. OpenAPI / Postman import
  is wired into the proxy (see §4.6 / §8.8).
- Nuclei tier-2 downloads only `http/` (the other protocol trees —
  `network/`, `dns/`, `ssl/`, … — are not runnable in v1 and would
  just inflate cache).
- XSS is reflected-only in v1 (both in the scan-engine fuzzer and the
  Checks engine); DOM-based and stored XSS are planned.
- In the **active fuzzer** (`FuzzingView.tsx` inventory), `file_upload`,
  `cms`, `tech`, `subdomain_takeover`, and `log4shell` are still marked
  **planned** — they have UI rows but aren't wired to runnable
  detectors. SSRF is handled by the **Checks engine** (`ssrf` active
  check) rather than the scan-engine fuzzer.
- CIDR expansion is IPv4-only in v1 (IPv6 literals work as single
  targets).
- Response body / request body capture is capped at 32 MB per side;
  larger payloads forward cleanly but only the initial prefix is
  stored and the exchange is tagged `body-truncated`.
- Coded Checks for OWASP 2025 A08 (Software/Data Integrity), A09
  (Logging & Alerting), and A10 (Mishandling of Exceptional Conditions)
  currently rely on Nuclei templates matched via the classifier — no
  hand-written probes yet.
- OOB / Interactsh-dependent Nuclei templates (~65) are parsed but
  skipped at runtime until a first-party collaborator service is
  shipped.

---

## 11. Quick reference — where things live in the repo

```
crates/corvex-desktop/
  src/
    main.rs           Tauri bootstrap, log + proxy + history + checks setup,
                      hydrates scope rules + retention policy at launch,
                      fans `exchange-new` / `ws-frame` / `intercept-pending`
                      broadcasts out as Tauri events
    commands.rs       Scan / probe / db / nuclei / wappalyzer / jarm commands
    proxy_cmd.rs      Proxy + intercept + replay + checks commands
                      (scope, retention, HAR, spec import, ws frames, checks)
    check_bridge.rs   Owns CheckRegistry, subscribes to proxy exchanges,
                      runs passive checks per in-scope exchange, persists
                      findings, emits `proxy://scan-finding`
    event_sink.rs     ReportSink that emits Tauri events per finding
    history.rs        SQLite scan-history DB
    log_bridge.rs     Pipes `tracing` events into the UI log panel
    params.rs         JSON shape for scan_start → corvex-core::cli::Cli
    probe_state.rs    In-memory registry of running probe UUIDs
    scan_state.rs     In-memory registry of running scan UUIDs
  ui/src/
    App.tsx           Root layout, view router, event wiring,
                      fuzzer-seed relay for "Send to Fuzzer"
    api.ts            Typed wrappers over invoke + listen (scan, probe,
                      proxy, scope, retention, HAR, spec import, intercept,
                      replay, checks, ws frames, taxonomy, wappalyzer)
    components/       One file per view: Dashboard, ProxyView (Traffic /
                      Intercept / Replay / Checks / Settings sub-tabs with
                      scope, retention, CA, browser, verify, troubleshoot
                      sections), FuzzingView + ActiveFuzzRunner, ScaView,
                      ProbingView + ProbeRunner + JarmInfo, DatabasesView,
                      HistoryView, HelpView, PluginsView, SettingsView,
                      plus small widgets (FindingsTable, StatsBar, LogPanel,
                      SeverityBreakdown, Sidebar, Toast, OnboardingTour,
                      ScanIndicator, Icons, TuningPicker, PluginPicker,
                      TitleBar, ThemeToggle, InfoTip, StatCard)
  tauri.conf.json     Tauri window + bundle + resource config
```

Shared engines under `crates/`:

| Crate | Purpose |
| --- | --- |
| `corvex-core` | HTTP client, config, scan runner, plugin registry, DBs, tuning, evasion, scope, CLI shape, VulnDB, port-scan, fuzz runner, SCA, curated Wappalyzer → CPE map (`sca::cpe_map`) |
| `corvex-plugins` | The 26 compile-time scan plugins + report sinks |
| `corvex-nuclei` | YAML template parser, store, runner |
| `corvex-sonar` | Service probing engine (scripted + static probes, fingerprints, JARM) |
| `corvex-proxy` | MITM proxy, CA authority, exchange store, intercept queue (request + response phases), replay, scope rules, retention ring buffer, WebSocket frame store, body-spill store, HAR writer, OpenAPI / Postman importer |
| `corvex-checks` | OWASP-taxonomy passive + active check registry; 6 passive (incl. `banner-cve`) + 7 coded active (incl. `boolean-blind-sqli`, `time-based-sqli`, `ssrf`, `hidden-params`) + `nuclei-active` umbrella + per-template rows |
| `corvex-intel` | Wappalyzer dataset loader, OWASP Top 10 taxonomy (`data/owasp/top10.yaml`), XSS canary + open-redirect payloads, hidden-parameter catalogue (`hidden_params`), Nuclei → OWASP classifier |

Checks engine source layout:

```
crates/corvex-checks/src/
  active/
    reflected_xss.rs       — A05 Injection, canary-reflection oracle
    sqli_error.rs          — A05, DBMS error-signature bank
    sqli_boolean.rs        — A05, trigram-ratio boolean-blind oracle
    sqli_time.rs           — A05, two-shot time-based oracle
    open_redirect.rs       — A01, sentinel-host redirect detection
    ssrf.rs                — A10, cloud-metadata + loopback probes
    hidden_params.rs       — A05, 13-group ~220-name wordlist
    nuclei_active.rs       — A03 umbrella, Critical+High+KEV/RCE tags
  passive/
    security_headers.rs    — A04 baseline (CSP, HSTS, XFO, …)
    verbose_errors.rs      — A02 error-leak patterns
    version_disclosure.rs  — A03 "Server: …/N.N" style banners
    insecure_cookies.rs    — A02 Secure / HttpOnly / SameSite audit
    stack_fingerprint.rs   — A03 Wappalyzer-schema detection
    banner_cve.rs          — A03 versioned-banner → vulndb CVE lookup
    nuclei_template.rs     — per-template adapter + OWASP classifier
  registry.rs              — CheckRegistry, default + bundled builders
```

---

## 12. TL;DR pitch

> Corvex Desktop gives a security engineer a Nikto-class signature
> scanner, an SQLMap-class SQLi engine, a Nuclei template runner
> (passive *and* active), an Nmap-class service prober, a mini-Burp
> intercepting proxy with full request-*and*-response intercept,
> replay, WebSocket frame capture, scope rules, retention policy, HAR
> export, OpenAPI / Postman import, an OWASP Top 10 v2025-aligned
> Checks engine (6 passive + 7 active coded checks + active-Nuclei
> umbrella + per-template rules), and an SBOM + binary + dependency
> vulnerability workbench — all in one Tauri binary, backed by a
> local NVD+EPSS mirror and a local SQLite history store, with live
> streaming UI, teachable in-app documentation, and zero required
> network access beyond the handful of updates the user initiates
> explicitly.
