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

**Corvex Desktop** (`corvex-rust`, current build `v0.1.0`) is a local,
offline-capable security assessment GUI that bundles **nine specialised
engines** plus **two cross-cutting enrichment layers** into a single
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
6. A **reconnaissance engine** for subdomain discovery via passive OSINT
   sources (Certificate Transparency / crt.sh, AlienVault OTX,
   CertSpotter) and active DNS work (record enumeration, AXFR attempts,
   wildcard detection, wordlist brute-force).
7. An **intercepting HTTP/HTTPS proxy** with its own Certificate
   Authority, per-session SQLite history, request *and* response
   interception, WebSocket frame capture, scope rules, retention
   policy, HAR export, OpenAPI / Postman spec import, and full replay
   (Burp/mitmproxy-class workflow).
8. A **Checks engine** that continuously evaluates proxy traffic
   against the OWASP Top 10 v2025 taxonomy with 6 passive and 7 coded
   active checks (plus an umbrella active-Nuclei runner and per-template
   rules), writing findings to the shared SQLite store.
9. A **Nuclei template runner** for community-maintained YAML detection
   rules, with bundled + on-demand template trees, surfaced as passive
   matcher-only checks against captured traffic *and* as an active
   umbrella check (`nuclei-active`) that fires eligible HTTP templates
   against a target.

On top of those nine engines, two cross-cutting layers tie the data
together:

- **Asset ecosystem** — a normalized, host-keyed view that joins
  observations from every engine (recon, probing, proxy, dashboard
  scans) into one record per host, with an Identity / Services / Stack
  / Endpoints / Findings / Related-assets / Timeline panel grid and a
  radial graph for pivoting between hosts.
- **Exploit-DB enrichment** — a local SQLite snapshot of the
  Exploit-DB CVE → public-exploit index (~50k entries) shipped with
  the binary and refreshable on demand. CVE-bearing findings (signature,
  Checks, SCA) automatically gain "Public exploits" rows with type,
  platform, author, verification flag, and a one-click source viewer.

Everything runs locally. The binary ships the signature databases,
Wappalyzer-compatible fingerprints, a curated Nuclei template set, the
OWASP Top 10 v2025 taxonomy, a 13-group / ~220-name hidden-parameter
wordlist, a curated Wappalyzer → CPE map for banner-CVE lookups, an
Exploit-DB snapshot, a default subdomain wordlist, and a private CA
generator. No SaaS, no cloud, no telemetry.

The GUI is a Tauri v2 shell (Rust core + React/TypeScript front-end). The
same Rust engines power both the headless CLI (`corvex`) and the desktop
binary (`corvex-desktop`) — the UI is a thin command surface, not a
re-implementation.

---

## 2. Who it's for

| Role | Why it helps |
| --- | --- |
| **Penetration testers** | Everything a baseline web-app engagement needs in one window: recon (DNS/probe + subdomain enumeration), discovery (crawler + Nuclei + signatures), active testing (SQLi, XSS, CMDi, LFI, XXE, SSTI), and an intercepting proxy with replay — plus an Asset view that pivots between hosts you've discovered without juggling Nikto, Nmap, SQLMap, Nuclei, Burp, mitmproxy, and Amass. |
| **Application security engineers** | SCA view analyses dependency manifests, binaries, and SBOMs against a local NVD+EPSS mirror. Proxy + Checks give continuous passive OWASP findings while a dev team exercises the app. CVE findings auto-link to public exploits via the bundled Exploit-DB snapshot. |
| **Red teamers** | Subdomain enumeration (passive + active brute-force) + port scan + service fingerprint + JARM per target, fuzz APIs under scope, use intercept/replay for tailored exploits. Runs air-gapped after the initial template/snapshot pull. |
| **Blue teams / detection engineers** | Proxy session DB plus exchange replay make it easy to reproduce attack traffic for signature authoring and detection tuning. HAR export feeds a SIEM or detection-rule tester. |
| **Security students / instructors** | Every view includes built-in technique documentation (SQLi techniques, tamper modules, DBMS specifics, JARM, OWASP categories, Nuclei template reference, recon source notes) — the app doubles as reading material, with a five-step Onboarding tour for new users. |
| **Compliance / SBOM owners** | Generate CycloneDX or SPDX SBOMs from source trees, import pre-existing SBOMs, enrich with NVD/EPSS and fix availability. |

---

## 3. Architecture at a glance

```
+-----------------------------------------------------------+
|                   corvex-desktop (Tauri v2)               |
|                                                           |
|   +-------------------------------------------+           |
|   |   React / TypeScript UI (ui/src)          |           |
|   |   Landing  ScanForm  Sidebar  ProxyView   |           |
|   |   AssetsView  AssetDetailView  ReconView  |           |
|   |   FindingsTable  ExploitHits  ...         |           |
|   +----------------------+--------------------+           |
|                          | Tauri invoke / events          |
|                          v                                |
|   +-------------------------------------------+           |
|   |   Rust command surface (src/*.rs)         |           |
|   |   commands.rs   proxy_cmd.rs   asset_cmd  |           |
|   |   recon_cmd.rs  history.rs   exploitdb.rs |           |
|   |   check_bridge  event_sink    params      |           |
|   +----+--------+--------+--------+--------+--+           |
|        |        |        |        |        |             |
|        v        v        v        v        v             |
|   corvex-  corvex-  corvex-   corvex-  corvex-           |
|   core     plugins  nuclei    sonar    proxy             |
|                                                           |
|   corvex-checks  corvex-recon  corvex-intel  (shared)    |
|                                                           |
+-----------------------------------------------------------+
          |                 |                 |
          v                 v                 v
    history.sqlite    proxy/ca/*.pem    nuclei-templates/
    exploitdb.sqlite  proxy/bodies/*    (bundled + cache)
    (app_data_dir)    (app_data_dir)
```

**Key properties:**

- Rust async runtime (`tokio`) handles all engine I/O.
- Tauri emits named events (`scan://{id}/finding`, `proxy://exchange-new`,
  `probe://{id}/open-port`, `recon://event`, `exploitdb://progress`,
  `log://line`) so the UI updates in real time with zero polling on hot
  paths.
- A single SQLite file (`history.sqlite`) stores scan-run history,
  proxy sessions / exchanges / WebSocket frames / findings, recon runs
  and recon findings, and per-session settings (scope rules, retention
  cap, intercept mode). WAL mode lets every engine share the file
  across connections.
- A separate `exploitdb.sqlite` (seeded from a bundled snapshot) carries
  the Exploit-DB CVE → exploit index. The bundled copy upgrades on app
  start unless the user has run their own sync.
- The Certificate Authority for HTTPS MITM is generated lazily in
  `<app_data_dir>/proxy/ca/` on first proxy start.
- The window is a custom-chrome Tauri window (no native title bar) with
  a four-section collapsible left rail (Workspace / Engine / Resources
  / Preferences) and a resizable findings pane; the experience is
  identical on Windows, macOS, and Linux.

---

## 4. Feature map — one paragraph per view

Top-level navigation ships **thirteen views** organized into four
sidebar sections:

- **Workspace** — Home, Assets, History
- **Engine** — Web scan, Probing, Recon, Fuzzing, Intercept, SCA
- **Resources** — Plugins, Databases
- **Preferences** — Settings, Help

A first-launch **Onboarding tour** (five-step modal, dismissible,
re-runnable from Settings) walks new users through Web scan → Active
fuzzing → History/Databases → the Asset view. Selection state is
persisted in `localStorage` as `corvexTourSeen`.

### 4.1 Home (landing)

The first screen on launch. Hero block ("Your unified security
workbench") with Defence / Offence chips, six capability cards
(Web vulnerability scan, Active fuzzing, Intercepting proxy on the
offence side; Service probing, Reconnaissance, Dependency analysis on
the defence side), and two CTAs — **Start a scan** (jumps to the
Dashboard) and **Read the manual** (jumps to Help). A footer carries
the version, build ID, and build profile so users can tell which
binary they're running.

### 4.2 Dashboard (signature scanner + active fuzzer)

The historical landing screen, now reachable via "Web scan". The
`ScanForm` exposes every knob a typical web assessment needs: host/URL
target, port, SSL on/off, IPv4/IPv6 preference, virtual host, custom
headers, evasion tricks (9 categories: random URL encoding, directory
self-reference, premature URL ending, fake parameters, TAB-as-spaces,
case-manipulation, Windows separators, session-splicing), tuning
filters, plugin selector, concurrency, active fuzzing toggles
(crawl depth, max URLs, scope, exclusion regex), 404 override,
user-agent, proxy, timeout/pause/max-time, and file output format. A
**preset system** at the form head saves and reloads named scan
configurations from `localStorage`, so common targets / WAF profiles
can be one-click recalled. Starting a scan spawns a Rust task that
streams `host-start`, `host-end`, `ssl`, `finding`, `summary`, and
`done` events through the Tauri event bus into a live `FindingsTable`,
a `StatsBar` (requests, findings, errors, rate, progress), a
`SeverityBreakdown` chip strip, and a resizable `LogPanel` fed by the
global `tracing` subscriber. A running scan shows a pulsing dot in the
sidebar Engine section and a dashboard-level ScanIndicator with a
cancel button. CVE-bearing findings expand to show matching public
exploits via the Exploit-DB integration. Finished scans are persisted
to the history DB.

### 4.3 Assets (unified host view)

A first-class view that flattens every observation against a normalized
host key. Host normalization (`asset_identity::normalize_host`) folds
case, strips trailing dots, and unwraps IPv6 brackets so `Example.COM.`,
`example.com`, and `[::1]` all collapse to one record.

**Assets list (`AssetsView`)** — single search box (LIKE on host, 200 ms
debounce, capped at 2,000 rows) and a sortable table: Host | Findings
| Exchanges | Open ports | Recon hits | Scans | Last seen. Clicking a
row opens the detail view; high-finding hosts are colour-flagged.

**Asset detail (`AssetDetailView`)** — two interchangeable modes
(toggle persisted to `localStorage`):

- **Panels mode** — responsive grid of seven panels:
  1. **Identity** — overview counts, primary IPs, /24 networks, DNS
     record table (A/AAAA/CNAME/MX/NS/TXT), first/last seen, ASN
     placeholder.
  2. **Services** — probe-discovered open ports with service /
     product / version, CPE chips, JARM hash link.
  3. **Stack** — Wappalyzer detections deduped by `(name, version)`
     with category colouring and per-detection path counts.
  4. **Endpoints** — `(method, path)` pairs derived from proxy
     traffic, sorted by request volume, with last status and
     finding count per row.
  5. **Findings** — deduplicated security findings by
     `(check_id, port, path, title)` with severity filters and
     occurrence counts. CVE rows expand to Exploit-DB hits.
  6. **Related assets** — three discovery strategies stitched
     together: same JARM (TLS-fingerprint cluster, often the same
     load balancer), same registrable suffix (sibling subdomains),
     same /24 network (IPv4 neighbours).
  7. **Timeline** — interleaved event log of probe runs, exchanges,
     findings, recon discoveries, and scans, newest first, with
     deep links back to source records.

- **Graph mode (`AssetGraph`)** — radial visualization centred on the
  target host. Concentric rings (Services → Stack → Endpoints →
  Findings → Related) cap at eight visible items per ring with an
  overflow pill; related-asset nodes are clickable and re-centre the
  graph on the chosen host.

**Cross-linking** — a small `AssetLink` component (icon button or chip)
appears in `FindingsTable`, `ProxyView` Traffic rows, `ReconView`
results, `ProbingView` open-port rows, and `HistoryView` host columns.
Clicking pushes the current host onto an `AssetNavProvider` breadcrumb
stack (depth 8) so investigations can pivot freely and back-navigate.

### 4.4 History

SQLite-backed scan log at `app_data_dir/history.sqlite`. Shows every
scan's host, parameters (as JSON), start/end times, status
(`running/done/cancelled/error`), total requests, findings, and errors.
Users can re-run any prior scan with a single click (the saved JSON
params re-populate `ScanForm`), delete individual entries, or clear
history. Each row's host column carries an `AssetLink` icon for a
one-click jump to the asset view.

### 4.5 Plugins

Read-only listing of the compile-time scan plugin registry shipped in
this build. Each row shows the plugin name, hook types (`start`,
`recon`, `scan`, `prefetch`, `postfetch`, `active`), description, full
name, and priority weight. Used for "what exactly runs during a
default scan?" briefings.

### 4.6 Probing (service fingerprinting)

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
**Configure** (persisted defaults read by the Dashboard's ScanForm),
**Scan modes** (what Rapid vs Deep actually do), **Probe families**
(scripted probes, static probes, fingerprint sets), **Datasets**
(bundled + user-supplied probe files with counts), **JARM** (TLS
fingerprint explainer + hash lookup), and **Directive format** (probe
file syntax reference). Extra probe files are merged into the live
probe DB on the fly. Open-port rows carry an `AssetLink` icon.

### 4.7 Recon (subdomain enumeration)

Two-tab surface (Run / History) for domain reconnaissance. Combines
**passive online sources** with optional **active DNS work** to build
a deduplicated subdomain list against a single seed domain.

**Passive sources** (concurrent, keyless):

- **crt.sh** — Certificate Transparency mirror, queried as
  `*.{domain}`.
- **AlienVault OTX** — community passive DNS index.
- **CertSpotter** — supplementary CT source with a different lookback
  window (catches short-lived staging certs crt.sh misses).

Sources fan out concurrently; one source failing does not abort the
run.

**Active phase** (sequential, system resolver):

1. Record enumeration — A, AAAA, MX, NS, TXT, SOA, CNAME on the seed.
2. Zone transfer (AXFR) attempted against every NS — almost always
   refused; success indicates misconfiguration.
3. Wildcard probe — random 32-char hex subdomain to detect catch-all
   IPs that would poison brute-force results.
4. Wordlist brute-force — `{prefix}.{domain}` resolved for each entry,
   skipping hits that match the wildcard. Concurrency slider 1–2000
   (default 500). Bundled default wordlist (~200 names) ships with the
   binary; users can supply their own file.

The Run pane streams `recon://event` payloads — `source_started`,
`source_finished`, `wildcard_detected`, `subdomain_discovered`,
`record_discovered`, `zone_transfer`, `brute_progress`, `complete`,
`failed`, `cancelled` — into per-source progress badges, a wildcard
banner, and a live results table. Each subdomain row carries three
cross-tool actions:

- **Add to Proxy scope** — append to the active session's include list.
- **Send to Checks** — inject a synthetic exchange (same pipeline as
  OpenAPI import) so passive checks can fire against the host.
- **Send to Fuzzer** — seed the Fuzzing view with `https://{host}/`.

Plus a bulk **Add all to Proxy scope**. Findings are batched (32 rows
or 150 ms) into `recon_runs` / `recon_findings` tables so a multi-
thousand-result run doesn't fsync per discovery, while UI events emit
immediately for live counters. The History tab lists past runs with
counts, status, duration, and a delete action that cascades to
findings.

### 4.8 Fuzzing (active injection)

Module inventory for the active fuzzing engine with 14 + 3 detectors:

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
`sqli_time_delay`, `tamper` chain, and `sqli_enumerate` list, and
accepts seed URLs forwarded from Proxy ("Send to Fuzzer") or Recon
("Send to Fuzzer") rows.

### 4.9 Intercept (proxy + replay + checks)

Five sub-tabs, wrapped in a toolbar that exposes the listener lifecycle
(Start / Stop, listen address, running badge, CA-ready badge), a
session-level **Export HAR** button, and an **Import spec** button that
seeds the active session from an OpenAPI 3 JSON or Postman v2.1
collection.

- **Traffic** — Live list of HTTP/HTTPS exchanges captured by the
  embedded MITM proxy. Each row shows method, scheme, host:port, path,
  status, size, duration, scope decision (`in`/`out`/`excluded`),
  origin (browser, replay, check, imported, recon-seed), and tags
  (`websocket`, `ws-extension`, `body-truncated`, …). An `AssetLink`
  icon next to the host pivots straight to the asset view. Clicking
  a row expands an in-place detail strip with IDs, req/res size, MIME,
  scope chip, and three cross-tool actions — **Send to Replay**,
  **Send to Checks**, and **Send to Fuzzer** (seeds the Active Fuzzing
  form with the captured URL and opens the Fuzzing view). WebSocket
  upgrades show a `ws` badge; expanding the row reveals a live frame
  list (opcode, direction, FIN flag, sequence, text/binary preview)
  fed by a `proxy://ws-frame` broadcast. Request / response bodies
  follow a two-tier cap: 512 KB inline in SQLite, anything bigger
  spills to a blob file under `proxy/bodies/`; a 32 MB hard cap per
  side triggers a `body-truncated` tag.
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
  exchanges (via *Send to Checks* on Traffic rows, or seeded from
  Recon) plus one or more active check IDs and clicks Run; findings
  stream in through `proxy://scan-finding` events and get persisted in
  the shared SQLite DB. Passive checks run automatically on every
  in-scope exchange via `check_bridge.rs`. CVE-bearing findings expand
  to show Exploit-DB hits.
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
     `scope_get` and hydrated into the listener at startup. Recon's
     "Add to Proxy scope" action writes through this same API.
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

### 4.10 SCA (Software Composition Analysis)

Four tabs:

- **Dependency analysis** — Point it at a directory of manifests
  (`Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`,
  `pom.xml`, `composer.json`, `Gemfile`, `pyproject.toml`,
  `packages.lock.json`, …) or at an existing SBOM (CycloneDX
  JSON/XML, SPDX JSON/tag-value). Emits findings tied to a CVE, CVSS,
  EPSS score/percentile, fix version, and affected component. CVE
  rows expand to show matching public exploits from the Exploit-DB
  snapshot.
- **Binary analysis** — ~50 static/CVE detectors run against compiled
  executables. Supports recursive directory scanning and archive
  extraction.
- **Results** — Unified findings list with severity filters, EPSS
  threshold slider (0.0–1.0), and optional fix-version output.
- **VulnDB** — Summary of CVE / CPE-match / EPSS / fix counts, last
  NVD and EPSS update timestamps, and an update button.

### 4.11 Databases (embedded datasets)

Seven tabs inspecting what ships inside the binary:

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
- **Exploit-DB** — Total exploit count, verified count, top types
  (`webapps`, `remote`, `dos`, …), top platforms, snapshot origin
  (`bundled` vs `user-synced`), upstream commit SHA, and last refresh
  timestamp. An **Update** button refreshes from
  `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`
  with `If-None-Match` short-circuiting; progress events
  (`exploitdb://progress`) drive a per-stage bar (download → parse →
  commit_lookup → done). A user-synced snapshot is preserved across
  app upgrades unless explicitly reset.

### 4.12 Settings

- **Appearance** — `system` / `light` / `dark` theme preference
  persisted in localStorage.
- **Typography** — Four font sizes (`small` / `medium` / `large` /
  `xlarge`) with a live preview.
- **Onboarding** — Reset the first-run onboarding tour so the
  five-step modal re-runs on next launch.

Service-probing defaults (scan mode, ports range, JARM, extra probe
files) live in **Probing → Configure** and are read by the Dashboard's
ScanForm at init — keeping engine-specific knobs next to the engine
they configure.

### 4.13 Help

Built-in manual: getting-started, every view explained, the asset
ecosystem (panels, graph, navigation), proxy workflow (CA trust,
scoping, intercept verdicts, replay), service-probing reference,
recon source notes, scenario recipes, a ScanForm field-by-field
reference, interface tips, data/storage locations, **Exploit-DB
enrichment**, the full bundled Nuclei template catalogue (fetched via
`nuclei_template_list`), a glossary, known limitations, and
troubleshooting. Searchable table of contents with scroll-spy
highlighting.

---

## 5. Backend surface (Tauri commands)

Every user action in the UI funnels through one of the following 65
commands (registered in `main.rs` and defined in `commands.rs`,
`proxy_cmd.rs`, `asset_cmd.rs`, and `recon_cmd.rs`). The rest is
rendering.

### Scan + history

| Command | What it does |
| --- | --- |
| `list_plugins` | Enumerate compile-time plugin registry. |
| `db_summary` | Row counts for every embedded web-signature DB. |
| `version_info` | Product name, semver, build ID, build profile. |
| `scan_start` | Spawn a scan (signature + optional active fuzz + SCA + portscan). Returns a UUID the UI subscribes to for events. |
| `scan_cancel` | Cooperatively cancel a running scan via a `CancellationToken`. |
| `scan_stats` | Snapshot counts from the scan's `GlobalState`. |
| `history_list` / `history_clear` / `history_delete` | SQLite history CRUD. |

### VulnDB / probe / fingerprints

| Command | What it does |
| --- | --- |
| `vulndb_summary` / `vulndb_update` | NVD+EPSS vulnerability DB inspector + refresher (daily / full mode). |
| `sonar_summary` | Inventory of scripted/static probes + fingerprint sets, with user-supplied extra files merged in. |
| `nuclei_summary` / `nuclei_template_list` / `nuclei_extras_download` / `nuclei_extras_remove` | Nuclei bundle inspector + tier-2 cache management. |
| `wappalyzer_summary` | Fingerprint dataset (embedded + seed). |
| `jarm_lookup` | Decompose a JARM hash into cipher/version + extensions digest and look up known matches. |
| `probe_start` / `probe_cancel` | Standalone service probing (target expansion, per-host concurrency, live events). |

### Recon

| Command | What it does |
| --- | --- |
| `recon_start` | Spawn a recon job (passive sources + optional active DNS / brute-force). Returns a run UUID; emits `recon://event`. |
| `recon_cancel` | Cooperatively cancel a running recon job. Idempotent. |
| `recon_runs_list` / `recon_run_get` | List recent runs (clamped 1–500, default 50) or fetch one run's metadata. |
| `recon_findings_for_run` | Stream of findings (subdomains / records / zone-transfer notes) for a run. |
| `recon_run_delete` | Delete a run and cascade-delete its findings. |

### Asset ecosystem

| Command | What it does |
| --- | --- |
| `asset_list` | Search across normalized hosts (LIKE, capped at 2,000) sorted by recency. |
| `asset_overview` | Single-host roll-up: counts, IPs, DNS records, /24 networks, first/last seen, ASN placeholder. |
| `asset_services` | Probe-discovered services for the host (port, service, product, version, CPE, JARM, TLS flag). |
| `asset_stack` | Wappalyzer detections deduped by `(name, version)` with category and per-detection path count. |
| `asset_endpoints` | Proxy `(method, path)` pairs ranked by exchange volume, with last status and finding count. |
| `asset_findings` | Deduplicated findings by `(check_id, port, path, title)` with severity sort and occurrence count. |
| `asset_related` | Three relationship sets — same JARM, same registrable suffix, same /24 network. |
| `asset_timeline` | Interleaved event log (probe / exchange / finding / recon / scan), newest first, with deep links. |

### Proxy (lifecycle, scope, retention, IO)

| Command | What it does |
| --- | --- |
| `proxy_start` / `proxy_stop` / `proxy_status` / `proxy_export_ca_pem` | Proxy session lifecycle + CA export. |
| `scope_get` / `scope_set` | Persisted include / exclude scope rule list (host, path regex, port). Path regexes are validated on save. |
| `retention_get` / `retention_set` | Ring-buffer `max_exchanges_per_session` policy; 0 disables eviction, values over 1,000,000 are clamped. |
| `proxy_export_har` | Stream the active session's captured exchanges out as a HAR 1.2 file (non-blocking; runs on the blocking pool so capture keeps going). |
| `proxy_import_spec` | Parse an OpenAPI 3 JSON or Postman v2.1 collection and seed the active session with one `Imported` exchange per endpoint so Checks can target never-visited routes. Reports `{imported, skipped, format}`. |
| `proxy_seed_host` | Inject a synthetic `GET /` exchange for a host into the active session. Used by Recon's *Send to Checks* button so freshly discovered subdomains can be passively scanned without browsing them. |
| `ws_frames_for_exchange` / `ws_frame_count` | Per-exchange WebSocket frame listing + count. Used by the traffic detail panel's frame viewer. |

### Proxy (traffic, intercept, replay, checks)

| Command | What it does |
| --- | --- |
| `exchanges_list` / `exchange_get` | Query the per-session exchange store. `exchange_get` returns a 1 MB-per-side preview plus full req/res size so the UI can show a "truncated" indicator. |
| `intercept_set_mode` / `intercept_get_mode` / `intercept_pending_list` / `intercept_resolve` / `intercept_drop_all` | Intercept queue control (applies to both request and response phases). |
| `replay_send` | Re-send a stored request with optional raw-byte edit. The result is persisted as a new exchange under origin `Replay{parent}` and broadcast. |
| `checks_list` / `findings_for_exchange` / `findings_for_session` / `checks_run` | Checks engine descriptors, per-exchange and per-session findings, on-demand active check runs. Descriptor rows carry their resolved OWASP category label + description from the active `top10.yaml`. |
| `owasp_taxonomy_info` | Version, release, source, and full category list for the active `top10.yaml`. |

### Exploit-DB

| Command | What it does |
| --- | --- |
| `exploitdb_summary` | Snapshot stats — total / verified row counts, by-type and top-platform breakdowns, origin (`bundled` / `user-synced`), upstream commit SHA, last refresh timestamp. |
| `exploitdb_by_cve` | Look up exploits by CVE ID. Case-insensitive; sorted verified DESC, date DESC. Backs every "Public exploits" row in Findings, SCA, and Asset findings. |
| `exploitdb_update` | Sync from `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` with `ETag`/`If-None-Match` short-circuiting. Emits `exploitdb://progress` events; replaces all rows in one transaction. |
| `exploitdb_fetch_source` | Download an exploit's raw source from GitLab and cache it on disk. Returns body + language hint for the in-UI source viewer. |

---

## 6. Event bus (what the UI listens to)

- `scan://{id}/start` — scan UUID, fired before any host is touched.
- `scan://{id}/host-start` / `host-end` — each target transition (host, port, SSL, banner, IP).
- `scan://{id}/ssl` — TLS certificate details for an SSL host.
- `scan://{id}/finding` — each new finding (streamed, not batched), with optional `cve`, `cvss`, `epss_score`, `epss_percentile`, `fix_version`, `component`, `component_version`.
- `scan://{id}/summary` — periodic aggregate.
- `scan://{id}/close` — end-of-stream marker.
- `scan://{id}/done` — terminal status (`done` / `cancelled` / `error`).
- `probe://{id}/host-start` / `host-end` / `open-port` / `summary` / `error` — service-probing lifecycle.
- `recon://event` — single multiplexed channel keyed by `run_id`. Event kinds: `source_started`, `source_finished`, `wildcard_detected`, `subdomain_discovered`, `record_discovered`, `zone_transfer`, `brute_progress`, `complete`, `failed`, `cancelled`.
- `proxy://exchange-new` — every captured HTTP exchange (summary).
- `proxy://ws-frame` — every captured WebSocket frame (exchange id, sequence, direction, opcode, FIN flag, base64 payload).
- `proxy://intercept-pending` — new item parked on the intercept queue (request or response phase).
- `proxy://scan-finding` — passive or active Check finding for a captured exchange.
- `exploitdb://progress` — Exploit-DB sync stages (`start`, `download`, `up_to_date`, `commit_lookup`, `parse`, `done`).
- `nuclei://progress` — Nuclei tier-2 download progress (when extras download is in flight).
- `log://line` — every `tracing` event the engine emits (level, target, message).

This push model is why the LogPanel, StatsBar, FindingsTable, Traffic
list, Intercept queue, Probe runner, and Recon view stay responsive
under heavy load — the front-end isn't polling anything on the hot
path. (The proxy listener-status banner is the one exception, and it
refreshes on a slow 2 s cadence.)

---

## 7. On-disk footprint

| Path (platform-resolved via `app_data_dir`) | Contents |
| --- | --- |
| `history.sqlite` | Scan history table; proxy sessions, exchanges, WebSocket frames, scope rules, retention setting, intercept mode, key/value settings, findings; recon runs and recon findings (`recon_runs` + `recon_findings`, FK cascade). WAL mode so every engine shares it safely. |
| `exploitdb.sqlite` | Exploit-DB snapshot — `exploits`, `exploit_cves`, `exploitdb_meta` tables. Seeded from a bundled snapshot on first launch and upgraded on app updates unless the user has run their own sync. Refreshable via the `exploitdb_update` command. |
| `proxy/ca/ca.cert.pem` + `proxy/ca/ca.key.pem` | Locally-generated Certificate Authority for HTTPS MITM. Regenerated on first proxy start if missing. |
| `proxy/bodies/<exchange-id>.{req,res}.bin` | Large request / response bodies that exceed the 512 KB inline cap are spilled here (up to the 32 MB per-side hard cap). Evicted alongside the parent exchange when retention trims. |
| `corvex/nuclei-templates/<tag>/` | Tier-2 Nuclei template cache (only `http/` is unpacked from the GitHub tarball). |
| Bundled in binary | Web-signature DBs, Nuclei tier-1 curated templates, Wappalyzer seed + dataset, JARM known hashes, default config, OWASP `top10.yaml`, hidden-parameter wordlist, Wappalyzer → CPE map, Exploit-DB seed snapshot, default subdomain wordlist (~200 names). |

Nothing is written outside the user's data dir. No registry entries. No
network calls unless the user explicitly clicks **Update VulnDB**,
**Update Exploit-DB**, **Download extras**, or runs a recon job against
online passive sources.

---

## 8. Concrete workflows Corvex accelerates

### 8.1 "I need a baseline scan of a new web app."

Web scan → enter host → Start. Signature engine runs every plugin
against the target, findings stream in severity-ranked in real time,
HTML report is optional. CVE-bearing rows expand to show matching
public exploits. One click.

### 8.2 "Is this app's dependency tree vulnerable?"

SCA → Dependency analysis → point at the project folder → Run. Findings
come back enriched with CVE, CVSS, EPSS, and (when published) a
fix-version — perfect for a ticket that tells a developer "upgrade
`lodash@4.17.15` to `4.17.21`, CVE-2020-8203, EPSS 0.91". CVE rows
expand to Exploit-DB hits so triage immediately sees whether a public
exploit exists and how recent it is.

### 8.3 "Reproduce and iterate on an attack observed in the wild."

Intercept → Start proxy (port 8888) → export CA → trust in browser →
exercise the app → find the interesting request in Traffic → Replay →
edit the body → send. Passive checks flag OWASP categories as you go;
active checks (SQLi, header issues, auth, injections) run on demand
against the selected exchange.

### 8.4 "What exposed services does this subnet actually run?"

Probing → targets `10.0.0.0/24` → Deep mode + JARM → Run. Stream of
open ports with product, version, CPE, and TLS JARM hash. Each
host's row carries an `AssetLink` icon — click it to land on the
Asset detail view and see every other observation against that host.

### 8.5 "Map every subdomain of a target before kickoff."

Recon → enter `target.com` → enable all three passive sources → toggle
**Active** → pick a wordlist → Start. Watch passive sources resolve in
parallel; if active is on, the wildcard probe runs first and the
brute-force phase streams progress. Click **Add all to Proxy scope**
to seed the proxy's include list with everything you found, or pick a
single host and **Send to Fuzzer** / **Send to Checks**.

### 8.6 "A new CVE dropped — am I exposed?"

SCA → VulnDB → Update (daily). Then re-run dependency or binary
analysis. The local NVD mirror means the whole flow works offline after
the initial update, and EPSS lets you triage which CVEs actually have
real-world exploitation pressure. If an entry has a public exploit, the
inline Exploit-DB row tells you within one click — including the
verification flag and the source body.

### 8.7 "I want to fuzz the login and search endpoints without writing
a single SQLMap command."

Web scan → enable Active → set scope/depth/max URLs → start. Or go to
Fuzzing → configure SQLi level/risk/technique/tamper-chain → Run. All
eight DBMS backends, five techniques, ~50 tampers, enumeration and
risk-3 exploitation are gated behind the same UI.

### 8.8 "Make the proxy scan my Burp-style workflow for OWASP findings."

Intercept → Start → Checks tab → review the built-in OWASP Top 10 v2025
library → passive checks (Security Headers, Verbose Errors, Version
Disclosure, Insecure Cookies, Stack Fingerprint, Banner CVE) run
automatically on every in-scope exchange → select a suspicious
exchange → run the specific active checks you care about (Reflected
XSS, Error-based SQLi, Boolean-blind SQLi, Time-based SQLi, Open
Redirect, SSRF, Hidden-Parameter Discovery, `nuclei-active`). Every
finding is persisted and re-loadable next session.

### 8.9 "Drive the Checks engine against an API I haven't clicked through yet."

Intercept → Start → **Import spec** → pick an OpenAPI 3 JSON or Postman
v2.1 collection → every endpoint lands in Traffic as an
`origin = Imported` row. Select rows → Send to Checks → Run the active
checks — the engine mutates parameters from the spec just as if you'd
recorded them live. Pair with **Scope rules** to exclude auth / logout
paths so the run doesn't nuke your session cookie.

### 8.10 "Drive the Checks engine against a freshly enumerated subdomain."

Recon → Run → on the result row click **Send to Checks**. The desktop
calls `proxy_seed_host` which writes a synthetic `GET /` exchange into
the active session under `origin = Imported`. Switch to Intercept →
Checks → pick the seeded row → Run passive + active checks. Same
pipeline as the OpenAPI workflow, no browser hop required.

### 8.11 "Archive a session for offline review or handoff."

Intercept → (session running or finished) → **Export HAR** → file
picker → HAR 1.2 file with every captured request / response (bodies
base64-encoded) is written. The export streams through the blocking
pool so capture keeps going on a live session. Counterpart for blue
teams: feed the HAR into your SIEM or detection-rule tester.

### 8.12 "Is this banner actually exploitable?"

Keep the proxy running while you browse → the **Stack Fingerprint**
passive check tags each response with detected products / versions
(Wappalyzer-schema dataset) → **Banner CVE** then queries the local
NVD mirror per versioned banner, produces one finding per CVE with
CVSS-mapped severity, adds EPSS score + percentile as evidence, and
caps at 25 findings per exchange to avoid flooding noisy pages. Each
CVE row expands to show Exploit-DB hits — verified rows on top, a
"View source" button to read the exploit body without leaving the
app. No vulndb = check silently disabled; run **Update VulnDB** once
from the Databases view to light it up.

### 8.13 "Pivot through everything we know about this host."

Anywhere you see a crosshair `AssetLink` icon (Findings, Traffic, Recon
results, Probing rows, History) — click it. The Asset detail view
opens with seven panels (Identity / Services / Stack / Endpoints /
Findings / Related / Timeline) drawn from a single normalized host
key. Switch to **Graph mode** for a radial overview, click a related
node (same JARM / same root domain / same /24) to recentre, and use
the breadcrumb stack (depth 8) to navigate back. Same target,
correlated across recon, probe, proxy, and dashboard scans, in one
place.

---

## 9. Why it's valuable to security professionals

1. **One binary, no plugin hunt.** Nikto + Nmap-service + SQLMap +
   Nuclei + a mini-Burp + an SCA scanner + a subdomain enumerator +
   an Exploit-DB lookup would normally be 7–9 tools with separate
   install paths, update flows, and output formats. Corvex collapses
   that into a single Rust binary with a consistent UI and a shared
   SQLite history/findings store.

2. **Runs offline.** The signature DB, Nuclei tier-1 templates,
   Wappalyzer seed, OWASP taxonomy, Exploit-DB snapshot, default
   subdomain wordlist, and probe data are all compiled into the
   executable. The NVD/EPSS mirror is local. The proxy's CA is
   self-generated. Good for classified/air-gapped environments —
   only Recon's online passive sources require network.

3. **Memory-safe + high-concurrency.** `tokio`-based async I/O, raw
   HTTP/1.x framing, OpenSSL with SNI / TLS 1.3 / ALPN, bounded
   `Semaphore`s for host + request concurrency, batched DB writes for
   Recon (32 rows / 150 ms), and cooperative cancellation. Long scans
   don't leak resources and can always be stopped mid-flight.

4. **Live telemetry instead of wait-and-hope.** Every subsystem emits
   events: scan findings, proxy exchanges, probe results, recon
   discoveries, Exploit-DB sync stages, and tracing logs. The UI
   reflects engine state within milliseconds of each underlying event.
   Great for demos, triage, and teaching.

5. **Cross-tool correlation built in.** The Asset model joins recon,
   probe, proxy, and dashboard observations against a single
   normalized host key. The Exploit-DB snapshot enriches every
   CVE-bearing finding inline. No exporting CSVs or pivoting through
   spreadsheets.

6. **Provenance built in.** Nuclei templates preserve original author
   attribution. The Wappalyzer dataset includes upstream license info.
   The SCA VulnDB records last NVD/EPSS update timestamps. The
   Exploit-DB snapshot records its origin (`bundled` vs `user-synced`)
   and upstream commit SHA. Every scan run is saved as JSON params you
   can audit or re-use.

7. **Fully scriptable surface.** Every UI action maps to one of the 65
   documented Tauri commands and a typed event; the same engines have
   a matching CLI (`corvex`) so CI pipelines, runbooks, and GUI
   sessions share one source of truth.

8. **Teachable.** The Help view (with a dedicated Asset-ecosystem and
   Exploit-DB section), the Fuzzing reference tables, the Probing
   directive format docs, the OWASP category descriptions, the bundled
   Nuclei catalogue, and a five-step Onboarding tour mean a junior
   engineer can learn the "why" without leaving the tool.

---

## 10. Known scope / limitations (v1)

- The GUI exposes *most* but not *all* CLI flags — VEX/triage and
  report merging/diffing are CLI-only today. OpenAPI / Postman import
  is wired into the proxy (see §4.9 / §8.9).
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
- **Recon** runs against one seed domain at a time (no batch /
  multi-domain mode in v1) and does not promote findings into the
  Asset table directly — discovered subdomains gain asset records
  only once they're proxied, probed, or scanned. The "same /24
  network" related-asset cluster is IPv4-only; IPv6 neighbours are
  not surfaced.
- **Asset model** has no parent/child hierarchy — relationships are
  lateral (peer discovery for investigation expansion) and there is
  no notion of a "primary" asset.
- **Exploit-DB** ships only the metadata index (~50k rows). Exploit
  *bodies* are fetched on demand from
  `gitlab.com/exploit-database/exploitdb` — the **View source**
  button requires network access the first time it's used per
  exploit (results are cached on disk afterwards).
- The proxy listener-status banner refreshes on a 2 s polling cadence
  (the rest of the proxy UI is event-driven).
