# Corvex Desktop — Comprehensive Product Overview (v2)

> A single-binary, cross-platform vulnerability discovery and web-application
> assessment workbench, built in Rust with a Tauri v2 front-end.
>
> This document explains what the desktop app is, what it does, which
> security-engineering workflows it accelerates, and how every view in the
> UI maps to a real engine in the codebase. It is intended as a briefing
> document you can hand to a colleague, a manager, or a prospective user.
>
> **v2 corrections (vs v1):** the engine count has been reconciled with
> the codebase — `FuzzingView`'s active fuzzer and the SQLMap-class SQLi
> engine share one runner (`ActiveFuzzRunner`), so they are one engine
> with sub-modules; the Nuclei runner is exposed through the Checks
> engine as the `nuclei-active` umbrella check plus per-template rows,
> so it is a sub-engine of Checks rather than a peer. The accurate
> count is **seven engines**, not nine.
>
> **v2.1 addendum:** five pieces of functionality landed shortly after
> the original v2 was written and are folded into the sections below —
> (a) a first-launch splash screen with live per-subsystem progress
> (so the window no longer looks frozen during CA generation / DB
> seeding); (b) **opt-in scan save** with auto-purge of unsaved runs at
> next launch; (c) **inline historical findings** in the History view
> (per-scan findings now persist in a new `scan_findings` table and
> re-render through `FindingsTable` on row expansion); (d) an embedded
> **unified rules catalog** (`rules.sqlite`) consolidating Nikto +
> OWASP ZAP + Burp BCheck rules with a `RulesPlugin` runtime executor;
> and (e) an in-UI **HTTP status code glossary** that decorates
> `HTTP 308`, `returned 404`, etc. inside finding messages with
> one-line explanations on hover.
>
> **v2.2 addendum (current build):** four further changes have landed
> since v2.1 and are reflected in the sections below — (i) an embedded
> **SNMP device-signature catalog** (`devices.sqlite`, ingested from
> `corvex-devicedb` YAMLs + IANA Private Enterprise Numbers + the
> IEEE OUI registry) that fires automatically in Deep probes (and is
> opt-in for Rapid probes), driving an eighth **Device** panel on the
> asset detail view and surfacing per-host SNMP / MAC chips on the
> Probing tab; (ii) **MAC-address capture** through the OS ARP / NDP
> cache, with vendor names resolved against the bundled IEEE OUI
> table; (iii) a **stateful probe runner** (`ProbeRunningProvider`)
> hoisted into the React root so a probe keeps streaming results in
> the background after the user navigates to a different sidebar
> view; and (iv) a Databases-view restructure — the legacy
> bincode-based "Web signatures" tab now reads from `rules.sqlite`
> directly (the standalone "Unified rules" tab is folded into it),
> and a new **Device signatures** tab exposes the SNMP catalog plus
> the IANA / IEEE reference tables. The Tauri command count is now
> **79** (was "65" in v1, "74" in the original v2, "78" in v2.1 — one
> new command: `device_db_summary`).

---

## 1. What Corvex is, in one paragraph

**Corvex Desktop** (`corvex-rust`, current build `v0.1.0`) is a local,
offline-capable security assessment GUI that bundles **seven specialised
engines** plus **two cross-cutting enrichment layers** into a single
installable application:

1. A **web signature scanner** (Nikto-class, ~7,200 tests) that runs every
   compile-time plugin against a target.
2. An **active injection engine** that covers XSS, SSTI, CRLF, XXE, LFI,
   command injection, open redirect, and CVE-chain exploits — including
   a full SQLMap-class SQLi sub-engine with 5 techniques (Error / Boolean
   / Time / UNION / Stacked), 8 DBMS backends, ~50 WAF-bypass tamper
   modules, post-detection enumeration, and risk-3 exploitation. The
   active fuzzer and the SQLi engine share `FuzzingView` and the same
   `ActiveFuzzRunner` Rust task — they are one engine with module-level
   detectors, not two parallel engines.
3. A **Software Composition Analysis (SCA)** engine backed by a local
   NVD + EPSS mirror with binary, manifest, and SBOM analysis.
4. A **service probing** engine (Nmap-class TCP service detection + JARM
   TLS fingerprinting). On every host the engine also fires, in parallel
   with the TCP sweep, an **SNMP v2c device-fingerprint probe** (UDP/161
   `sysDescr.0` + `sysObjectID.0`, matched against a bundled signature
   catalog of vendor / OS / device-type triples) and a **MAC capture
   pass** (post-scan OS ARP / NDP cache lookup, vendor resolved through
   the bundled IEEE OUI registry, with the IANA Private Enterprise
   Numbers table as a sysObjectID-prefix fallback). Both fire
   automatically in Deep mode and are opt-in checkboxes in Rapid mode.
5. A **reconnaissance engine** for subdomain discovery via passive OSINT
   sources (Certificate Transparency / crt.sh, AlienVault OTX,
   CertSpotter) and active DNS work (record enumeration, AXFR attempts,
   wildcard detection, wordlist brute-force).
6. An **intercepting HTTP/HTTPS proxy** with its own Certificate
   Authority, per-session SQLite history, request *and* response
   interception, WebSocket frame capture, scope rules, retention
   policy, HAR export, OpenAPI / Postman spec import, and full replay
   (Burp/mitmproxy-class workflow). Traffic auto-clusters by endpoint
   pattern (`/api/users/:id`) with anomaly badges; an automatic CSRF
   token store extracts and re-injects tokens across browse / replay /
   active-checks / fuzz; and conditional intercept rules
   (host / path / method / status / content-type / header) replace the
   blunt off/request/response/both switch.
7. A **Checks engine** that continuously evaluates proxy traffic
   against the OWASP Top 10 v2025 taxonomy with 6 passive and 7 coded
   active checks, plus an embedded **Nuclei template runner** surfaced
   both as the umbrella active check `nuclei-active` (drives the
   bundled HTTP template store against a target) and as per-template
   rows in the Checks library (so users can enable / disable individual
   community-maintained YAML rules). The runner is also surfaced
   passively as matcher-only checks against captured traffic. Findings
   stream to the shared SQLite store.

On top of those seven engines, two cross-cutting layers tie the data
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
Exploit-DB snapshot, a default subdomain wordlist, the unified rules
catalog (`rules.sqlite`), the SNMP device-signature catalog
(`devices.sqlite`, including the IANA Private Enterprise Numbers
table and the IEEE OUI registry), and a private CA generator. No
SaaS, no cloud, no telemetry.

The GUI is a Tauri v2 shell (Rust core + React/TypeScript front-end). The
same Rust engines power both the headless CLI (`corvex`) and the desktop
binary (`corvex-desktop`) — the UI is a thin command surface, not a
re-implementation.

> **Crates vs engines.** The codebase is organised into ten Rust crates
> (`corvex-core`, `corvex-checks`, `corvex-recon`, `corvex-intel`,
> `corvex-nuclei`, `corvex-sonar`, `corvex-proxy`, `corvex-plugins`,
> `corvex-rules`, `corvex-devicedb`) that do **not** map one-to-one
> onto the seven user-facing engines — `corvex-nuclei`, for instance,
> is a crate consumed by the Checks engine rather than a standalone
> engine; `corvex-rules` is the runtime executor for the unified
> Nikto + ZAP + Burp BCheck catalog and is consumed by both the
> signature scanner and the legacy `TestsPlugin`; `corvex-devicedb`
> is the SNMP signature matcher consumed by the probing engine.
> Crate boundaries follow code-reuse needs (the same engines power
> both the desktop GUI and the CLI); engine boundaries follow
> user-facing workflow surfaces.

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
|   corvex-checks   corvex-recon    corvex-intel  (shared) |
|   corvex-rules    corvex-devicedb               (shared) |
|                                                           |
+-----------------------------------------------------------+
          |                 |                 |
          v                 v                 v
    history.sqlite    proxy/ca/*.pem    nuclei-templates/
    exploitdb.sqlite  proxy/bodies/*    (bundled + cache)
    rules.sqlite      (app_data_dir)
    devices.sqlite
    (app_data_dir)
```

The boxes labelled `corvex-*` are **crates**, not engines. The seven
engines listed in §1 are user-facing surfaces composed from these
crates: e.g. the Checks engine spans `corvex-checks` (passive +
hand-written active checks) plus `corvex-nuclei` (template runner used
by the `nuclei-active` umbrella check); the active injection engine
lives mostly in `corvex-plugins` driven from `corvex-core`.

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
- A **first-launch splash screen** (`SplashScreen.tsx` +
  `init_progress.rs`) gates the main React tree on the backend's heavy
  init pipeline. `setup()` returns immediately after registering the
  cheap in-memory state, then a background task opens each disk-touching
  subsystem in turn — Recon DB → Exploit-DB index → Scan history →
  Service probe store → Asset DB → Proxy state & CA — flipping a per-step
  status (`Pending` → `Running` → `Ok` / `Failed`) and emitting
  `app://init-step` events. The splash renders one row per step with a
  progress bar; when every step has reported its terminal state the
  backend emits `app://init-ready` and the splash unmounts to reveal the
  app. Steps fail-soft (a failed Exploit-DB seed still lets the rest of
  the app run), and the `init_status` command lets the splash recover an
  accurate snapshot if it mounts after the first event has already
  fired.
- A **unified rules catalog** (`rules.sqlite`) is **embedded into the
  desktop binary at build time** (`build.rs` + `rules_embed.rs`) and
  extracted on first launch to
  `<app_data_dir>/dev.fazminnizam.corvex-rust/rules.sqlite`, with a
  cwd / exe-dir override path so power users can swap catalogs without
  rebuilding. The catalog ingests **Nikto + OWASP ZAP + Burp Suite
  BChecks** through `corvex-rules-builder`, lowers each rule to a
  `match_spec_json` blob, and is consumed at scan time by `RulesPlugin`
  alongside the legacy `TestsPlugin`. The desktop runs both in
  side-by-side mode by default; the CLI flag `--rules-only` flips
  ownership for parity validation.
- A **device-signature catalog** (`devices.sqlite`) is embedded
  through the same `build.rs` mechanism (`device_embed.rs`) and
  extracted to the same per-user namespace
  (`<app_data_dir>/dev.fazminnizam.corvex-rust/devices.sqlite`), with
  the same cwd / exe-dir override chain. The file ships the SNMP
  device-fingerprint catalog (~hundreds of vendor / OS / device-type
  YAMLs lowered into matchable rows by `corvex-devicedb-builder`), the
  IANA Private Enterprise Numbers reference table, and the IEEE OUI
  registry (MA-L / MA-M / MA-S tiers). The probing engine reads it
  read-only on every Deep host (and on Rapid hosts where the user
  ticks the SNMP / MAC checkboxes); the Asset detail view's Device
  panel surfaces the latest match per host.
- A **vulndb warm-up** task fires from `setup()` (after splash init
  has begun) and opens `vulndb.sqlite` on the blocking pool, so the
  schema-v2 vendor/product index on `cpe_matches` is hot and
  index-resident before the user's first SCA scan. Skipped when the
  file isn't on disk yet (so users who never run SCA don't pay the
  warm-up cost).
- A **stateful probe runner** (`probe_running.tsx`'s
  `ProbeRunningProvider`) lives at the React root, above the App
  router. It owns the active probe id, listener handles, and
  accumulated result tables (open ports, device matches, MAC
  resolutions, errors, summary, persisted form inputs) so the user
  can navigate from the Probing view to any other sidebar view —
  Recon, Asset, Settings — and the probe keeps streaming results in
  the background. Returning to Probing re-renders the latest state
  with no replay or refetch.

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

> Note that the **Engine** sidebar section has six entries (Web scan,
> Probing, Recon, Fuzzing, Intercept, SCA), which is one fewer than the
> seven engines in §1. The Checks engine does not have its own
> top-level sidebar entry — it lives as the **Checks** sub-tab inside
> Intercept (§4.9) and runs continuously against in-scope proxy
> traffic. This is intentional: Checks is a passive layer over the
> proxy plus an on-demand active runner you launch from selected
> exchanges, not a standalone target-driven workflow.

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
exploits via the Exploit-DB integration. Status codes referenced in a
finding message (`HTTP 308`, `returned 404`, `MOVED PERMANENTLY (301)`,
…) are decorated by an in-UI **HTTP status glossary**
(`util/httpStatus.ts`) so users hover any code to see a one-line
plain-English summary — covers the common 1xx / 2xx / 3xx / 4xx / 5xx
codes (including 418, 429, and the WebDAV / RFC 6585 family) without
leaving the table.

Once a scan finishes, a **Save scan** button appears on the
FindingsTable toolbar. Without it, the run sits in `history.sqlite`
with `saved = 0` and is purged the next time the app launches —
**opt-in retention** keeps the History list from filling with throwaway
exploratory scans. Clicking *Save scan* flips the row's `saved` flag
via `history_set_saved` and the row stays put forever (or until the
user deletes it). In-flight `running` scans always show in History so
a mid-scan navigation doesn't hide them.

This view drives engines #1 (web signature scanner) and #2 (active
injection engine) from a single form: leaving the active toggles off
runs the signature engine alone; turning them on hands the crawler's
URL set off to the active injection engine to fuzz.

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

- **Panels mode** — responsive grid of eight panels:
  1. **Identity** — overview counts, primary IPs, /24 networks, DNS
     record table (A/AAAA/CNAME/MX/NS/TXT), first/last seen, ASN
     placeholder.
  2. **Device** — latest SNMP device-fingerprint match for the host
     (vendor + OS chip, device-type chip, source attribution,
     `sysDescr` and `sysObjectID` evidence) plus the latest MAC
     observation (MAC string + IEEE OUI vendor chip). Empty when no
     SNMP probe has fired (or fired and missed) and no MAC was
     captured. Sourced from `probe_device_match` and
     `probe_host_mac` rows joined into the asset overview.
  3. **Services** — probe-discovered open ports with service /
     product / version, CPE chips, JARM hash link.
  4. **Stack** — Wappalyzer detections deduped by `(name, version)`
     with category colouring and per-detection path counts.
  5. **Endpoints** — `(method, path)` pairs derived from proxy
     traffic, sorted by request volume, with last status and
     finding count per row. A **[Flat] / [Clustered]** toggle
     (persisted to `localStorage`) re-aggregates rows over endpoint
     patterns (e.g. `/api/users/:id`) using the same cluster engine
     that powers Traffic clustering.
  6. **Findings** — deduplicated security findings by
     `(check_id, port, path, title)` with severity filters and
     occurrence counts. CVE rows expand to Exploit-DB hits.
  7. **Related assets** — three discovery strategies stitched
     together: same JARM (TLS-fingerprint cluster, often the same
     load balancer), same registrable suffix (sibling subdomains),
     same /24 network (IPv4 neighbours).
  8. **Timeline** — interleaved event log of probe runs, exchanges,
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

**Opt-in retention.** Only scans the user explicitly clicked **Save
scan** on (Dashboard) survive a relaunch — `HistoryDb::open` runs
`DELETE FROM scans WHERE saved = 0` at startup, which cascades through
the new `scan_findings` table via `ON DELETE CASCADE`. This keeps the
history surface focused on intentional records rather than every
exploratory ten-second probe. In-progress (`running`) scans are still
shown so opening History mid-scan never hides what's live.

**Inline findings.** Each row is expandable (chevron in the leftmost
column). Expanding fires `history_findings(id)` against the
`scan_findings` table — a per-finding persistence layer added so the
History view can re-render the full FindingsTable for a past run
without re-scanning. The fetch is lazy (cached per row), keyed by
`scan_id`, and renders through the same `FindingsTable` component the
Dashboard uses, so severity filters, CVE-expand-to-Exploit-DB, JSON
copy, and the HTTP status glossary all work identically against
historical data.

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
JARM toggle, **SNMP fingerprint** toggle, **MAC lookup** toggle, and
host concurrency. Targets accept IPv4/IPv6 literals, hostnames
(DNS-resolved), CIDR blocks (`/8` safely capped at 65,536 hosts),
dash-ranges (`10.0.0.5-10.0.0.12`), short-octet ranges
(`192.168.1.10-12`), and comma-separated lists.

Each open port emits a `probe://{id}/open-port` event carrying service
name, product, vendor, version, info banner, CPE list, TLS flag, JARM
hash, and raw banner. In addition, when SNMP fingerprinting is
enabled (always on in Deep mode; opt-in in Rapid via the *SNMP device
fingerprint* checkbox) the engine fires an SNMP v2c GET against
UDP/161 in parallel with the TCP sweep, asks for `sysObjectID.0` /
`sysDescr.0`, and runs the response through `corvex-devicedb`'s
matcher (longest sysObjectID-prefix wins; sysDescr substrings and
fancy-regex patterns AND inside a clause). A successful match emits
a `probe://{id}/device-match` event carrying vendor, OS,
device-type, source attribution (`sysObjectID` / `sysDescr` /
`fallback`), and the raw evidence — surfaced as a per-host **Device**
chip in the run table and persisted to `probe_device_match`. When
**MAC lookup** is enabled (Deep mode default; opt-in in Rapid via
the *MAC address scan* checkbox) the engine reads the OS ARP / NDP
cache after the TCP scan completes, resolves the MAC against the
bundled IEEE OUI table, and emits `probe://{id}/mac-resolved` with
the MAC string + vendor chip — only L2-adjacent hosts return useful
data, routed targets surface the upstream router's MAC instead.

The view has tabs for **Run** (live progress, with per-host Device /
MAC chips next to the open-port count), **Configure** (persisted
defaults read by the Dashboard's ScanForm), **Scan modes** (what
Rapid vs Deep actually do, including which Deep-only follow-up
probes fire), **Probe families** (scripted probes, static probes,
fingerprint sets), **Datasets** (bundled + user-supplied probe files
with counts; cross-links to the Databases view's *Device signatures*
tab for the SNMP catalog + IANA / IEEE reference tables), **JARM**
(TLS fingerprint explainer + hash lookup), and **Directive format**
(probe file syntax reference). Extra probe files are merged into the
live probe DB on the fly. Open-port rows carry an `AssetLink` icon.

A running probe **stays alive when the user navigates away.** The
runner state lives in `ProbeRunningProvider` (a React context
mounted at the app root, above the main view router) so switching
to Recon / Asset / Settings keeps the listener attached, results
keep streaming into `probe_open_ports` / `probe_device_match` /
`probe_host_mac`, and returning to Probing re-renders the live
state without replay or refetch. The Cancel button and the form
inputs are persisted there too.

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
- **Pause** — append an Include intercept rule (HostGlob, request
  phase) so the next first-contact request to the discovered subdomain
  is queued for inspection. Symmetric counterpart of *Add to Proxy
  scope* — Scope admits, Pause queues for review.
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

Module inventory for the active injection engine — one engine, multiple
sub-modules under one runner (`ActiveFuzzRunner`). 14 ready detectors
plus 6 planned detectors plus 3 CVE-chain entries:

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
("Send to Fuzzer") rows. Cluster-derived seeds (Traffic → cluster
row → Send to Fuzzer) carry the pattern URL plus
`InjectionPoint::PathSegment(usize)` hints so per-segment fuzzing
can target the parameterised slots; the seed banner shows the
cluster context (member count, sample paths). Runner consumption of
the path-segment hints is wired up to the `FuzzTarget::from_pattern_url`
boundary; full per-segment injection in the active runner is a
follow-up (see §10).

> The SQLi sub-modules (`sqli_error`, `sqli_boolean`, `sqli_time`,
> `sqli_union`, `sqli_stacked`, `sqli_enumerate`, `sqli_exploit`) are
> *part of* the active injection engine, not a separate engine — they
> share the same `ActiveFuzzRunner` task, the same parameter
> mutator, and the same finding pipeline as the other injection
> detectors. Engine #2 in §1 is one engine with SQLMap-class depth in
> one of its module families.

### 4.9 Intercept (proxy + replay + checks)

Five sub-tabs, wrapped in a toolbar that exposes the listener lifecycle
(Start / Stop, listen address, running badge, CA-ready badge), a
session-level **Export HAR** button, and an **Import spec** button that
seeds the active session from an OpenAPI 3 JSON or Postman v2.1
collection.

- **Traffic** — Live list of HTTP/HTTPS exchanges captured by the
  embedded MITM proxy. A **[Flat] / [Group by endpoint]** chip at the
  top (state in `localStorage`) switches between the per-request view
  and a **clustered view** that collapses URL siblings (`/api/users/1`,
  `/api/users/2`, …) into a single `/api/users/:id` row. The
  `derive_pattern` heuristic recognises numeric IDs, UUIDs, MongoDB
  ObjectIDs, and slug-shaped segments while preserving alpha words and
  numeric-stem filenames. Cluster rows carry **anomaly badges** for
  four classes — `AuthMismatch` (mixed authenticated/anonymous), 
  `StatusOutlier` (one status code dominates, others are rare),
  `SizeOutlier` (response body sits outside the cluster's running
  Welford variance band), and `RateLimited` (429s appearing) — and
  lazy-load member instances on expand. Each row (flat or cluster)
  shows method, scheme, host:port, path, status, size, duration, scope
  decision (`in`/`out`/`excluded`), origin (browser, replay, check,
  imported, recon-seed), and tags (`websocket`, `ws-extension`,
  `body-truncated`, `csrf-injected`, …). An `AssetLink` icon next to
  the host pivots straight to the asset view. Clicking a row expands
  an in-place detail strip with IDs, req/res size, MIME, scope chip,
  and three cross-tool actions — **Send to Replay**, **Send to
  Checks**, and **Send to Fuzzer** (seeds the Active Fuzzing form with
  the captured URL and opens the Fuzzing view); cluster rows forward
  the pattern URL plus path-segment injection hints. WebSocket upgrades
  show a `ws` badge; expanding the row reveals a live frame list
  (opcode, direction, FIN flag, sequence, text/binary preview) fed by
  a `proxy://ws-frame` broadcast. Request / response bodies follow a
  two-tier cap: 512 KB inline in SQLite, anything bigger spills to a
  blob file under `proxy/bodies/`; a 32 MB hard cap per side triggers
  a `body-truncated` tag. Cluster anomalies that flip on for the first
  time also emit one Finding per `(method, host, port, pattern, kind)`
  to the shared findings store via `check_bridge::attach_cluster_anomalies`.
- **Intercept** — Queue of requests *and* responses paused by the
  user's intercept mode (`off` / `request` / `response` / `both`),
  optionally narrowed by the **conditional intercept rules** configured
  in Settings → Intercept rules. A `⚠ N rules active` chip next to the
  mode selector surfaces when rules are in play. Each pending item can
  be **Forwarded**, **Edited and forwarded** (raw bytes replaced), or
  **Dropped**. Subscribes to `proxy://intercept-pending` events for
  zero-poll updates, with a 5-minute auto-forward safety timeout so a
  forgotten pause can't hang the browser.
- **Replay** — Pick a captured exchange, optionally mutate its raw
  request bytes, and re-send through the same upstream client. The
  replayed exchange is written back to the session DB under origin
  `Replay{parent}` so replays stack alongside the original request in
  Traffic. The toolbar carries an **Apply CSRF** checkbox (default on)
  that can be flipped off to deliberately reproduce a token-mismatch
  failure; with it on, the proxy's CSRF store auto-injects the
  freshest matching token before the request leaves.
- **Checks** — This sub-tab is the user-facing surface of engine #7
  (the Checks engine). Library of passive + active checks grouped by
  OWASP Top 10 v2025 category (version, release date, and description
  sourced from the active `top10.yaml` taxonomy; a banner at the top
  surfaces version + upstream link). The current build ships **6
  passive checks** (Security Headers, Verbose Errors, Version
  Disclosure, Insecure Cookies, Stack Fingerprint, Banner CVE
  Cross-Reference), **7 coded active checks** (Reflected XSS, Error-
  based SQLi, Boolean-blind SQLi, Time-based SQLi, Open Redirect,
  SSRF, Hidden-Parameter Discovery), an **active Nuclei umbrella**
  (`nuclei-active`) that drives the bundled HTTP template store against
  a chosen target, and **per-template rows** for every supported
  Nuclei template so users can enable / disable individual rules.
  Together the umbrella + per-template rows are the Nuclei sub-engine
  — there is no separate "Nuclei" workflow surface, only its
  exposure as part of Checks (and as a passive matcher-only layer
  via `check_bridge.rs`). The library supports free-text search,
  "enabled only" filter, and OWASP-category descriptions in header
  tooltips. The user picks one or more exchanges (via *Send to Checks*
  on Traffic rows, or seeded from Recon) plus one or more active check
  IDs and clicks Run; findings stream in through `proxy://scan-finding`
  events and get persisted in the shared SQLite DB. Passive checks run
  automatically on every in-scope exchange via `check_bridge.rs`. Every
  coded active check (Reflected XSS, Open Redirect, the four SQLi
  variants, SSRF, Hidden-Parameter Discovery) routes its probes through
  the CSRF store's `send_with_csrf` helper so checks don't 419 against
  CSRF-protected endpoints. CVE-bearing findings expand to show
  Exploit-DB hits.
- **Settings** — Nine-section guided setup:
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
  5. **Intercept rules** — conditional `{ kind, phase, conditions[],
     enabled }` rule list that narrows what the off/request/response/
     both mode selector pauses. Conditions: `HostGlob`, `PathRegex`,
     `MethodIn`, `ContentTypeContains`, `StatusRange`, `HasHeader`
     (with optional value regex). Conditions AND inside a rule, OR
     across rules of the same kind; **exclude wins**. Empty rule list
     reverts to mode-only behaviour. Malformed regex is rejected at
     Save time and **fails closed** (a malformed Include rule never
     fires, so it can't silently widen scope). Four bundled preset
     chips append common configurations: *Skip static assets*, *Only
     mutating requests*, *Only auth endpoints*, *Only error responses*.
     Edits take effect on the next request — no listener restart.
     Persisted in the new `proxy_intercept_rules` table; conditions
     are stored as a tagged-enum JSON blob so future condition kinds
     don't need a schema migration.
  6. **CSRF tokens** — full editor for the CSRF rule store with a live
     status panel (rule | host | truncated value | observed-ago).
     Each rule pairs a `TokenSource` (`HtmlInput`, `MetaTag`,
     `JsonPath`, `SetCookie`, `ResponseHeader`) with a `TokenInject`
     (`FormField`, `JsonField`, `Header`, `Cookie`); the proxy
     observes responses, harvests the token, and re-injects it into
     subsequent matching requests so browsing, replay, active checks,
     and the fuzzer don't 419 on token expiry. JSON-injecting into a
     form-encoded body refuses to corrupt the body; cookie-injecting
     preserves siblings on the existing `Cookie` header; JSON
     injection creates the parent key if the JSON pointer doesn't
     resolve. Six rules ship as bundled defaults on first run
     (Laravel `_token`, Rails `authenticity_token` + meta tag,
     ASP.NET `__RequestVerificationToken`, Django
     `csrfmiddlewaretoken`, Angular `XSRF-TOKEN` cookie). The status
     panel subscribes to `proxy://csrf-observed` for zero-poll
     updates. Successful injections tag the affected exchange with
     `csrf-injected`. Persisted in the new `proxy_csrf_rules` table.
  7. **Retention** — configurable ring buffer `max_exchanges_per_session`
     (presets 1k / 5k / 20k / 100k / unlimited, default 5,000). On
     every ~250 ms flush the writer evicts oldest rows plus their
     dependent WebSocket frames and scan findings; the cap is
     per-session (each Start / Stop cycle gets its own budget).
     Persisted via `retention_set` / `retention_get`.
  8. **Verify** — smoke-test checklist (open an HTTP then an HTTPS
     page, confirm Traffic rows appear, body visible).
  9. **Troubleshooting** — common failure modes (CA not trusted,
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

Eight tabs inspecting what ships inside the binary:

- **Web signatures** — Surface for the embedded `rules.sqlite` catalog
  consolidating **Nikto**, **OWASP ZAP**, and **Burp Suite BChecks**
  into a single SQLite file (this is where the legacy bincode
  `db_tests` / `db_outdated` / `db_favicon` / etc. tables used to be
  surfaced — every web check now flows through `RulesPlugin` against
  the unified catalog, so the standalone *Unified rules* tab from
  v2.1 is folded in here). Shows the resolved on-disk path (after
  cwd / exe-dir / extracted-blob lookup), schema version, builder
  timestamp, total ingested vs total executable rule counts (rules
  with non-NULL `match_spec_json` are runnable by `RulesPlugin`), an
  invalid-JSON sanity counter, a per-source breakdown (rows ingested
  + rows lowered + lowering coverage % + pinned upstream commit SHA
  per tool), and a per-(source, severity) breakdown sorted critical
  → info. When `rules.sqlite` is absent the tab renders a build
  instruction
  (`cargo run -p corvex-rules-builder -- --sources rules-sources --output rules.sqlite`)
  and reminds the user that the desktop falls back to legacy
  bincode-only behaviour silently in that case. (The legacy
  `db_summary` Tauri command is still wired for back-compat with
  any out-of-tree consumers of the bincode counts but is no longer
  read from this tab.)
- **Probing** — Scripted probes (SSH, HTTP, TLS, SMTP, FTP, MySQL, …),
  static banner probes, fingerprint sets, and JARM-known entries.
  Extra probe files configured in Settings are counted here. Cross-
  links to the Device signatures tab for the SNMP-fingerprinting
  side of probing.
- **Device signatures** — Surface for the embedded `devices.sqlite`
  catalog driving SNMP-based device fingerprinting and MAC-vendor
  resolution. Shows total **SNMP device entries** (one per signature
  YAML), distinct **vendors** and **device types** (`network`,
  `firewall`, `pdu`, `printer`, `server`, `wireless`, …), total
  **discovery clauses** (with a count of clauses disabled because
  they require an active SNMP follow-up GET the matcher cannot
  issue), totals for **sysObjectID prefixes**, **sysDescr
  substrings**, and **sysDescr regexes** across the catalog, plus
  the **IANA Private Enterprise Numbers** row count and the **IEEE
  OUI registrations** row count (MA-L 24-bit + MA-M 28-bit + MA-S
  36-bit). Provenance pane explains the build pipeline
  (`corvex-devicedb-builder` over the YAMLs in
  `crates/corvex-devicedb/data/devices/`, the canonical IANA text
  file, and the IEEE OUI JSON), the reader's schema-version
  rejection logic for stale extracted copies, and cross-links to
  Probing for live fingerprinting controls. When the catalog
  hasn't been built yet the tab renders a build instruction
  (`.\scripts\build-devicedb-snapshot.ps1`) and reminds the user
  that SNMP fingerprinting is effectively disabled until a real
  catalog is embedded.
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

Every user action in the UI funnels through one of the following 79
commands (registered in `main.rs` and defined in `commands.rs`,
`proxy_cmd.rs`, `asset_cmd.rs`, and `recon_cmd.rs`). The rest is
rendering.

### Init / lifecycle

| Command | What it does |
| --- | --- |
| `init_status` | Snapshot of the splash screen's per-step init progress (Recon DB, Exploit-DB, History, Probe store, Asset DB, Proxy/CA). Returns a `{ steps[], ready }` shape so a late-mounting splash can recover the same state the live `app://init-step` events would have rendered. |

### Scan + history

| Command | What it does |
| --- | --- |
| `list_plugins` | Enumerate compile-time plugin registry. |
| `db_summary` | Row counts for every embedded web-signature DB. |
| `version_info` | Product name, semver, build ID, build profile. |
| `scan_start` | Spawn a scan (signature + optional active fuzz + SCA + portscan). Returns a UUID the UI subscribes to for events. |
| `scan_cancel` | Cooperatively cancel a running scan via a `CancellationToken`. |
| `scan_stats` | Snapshot counts from the scan's `GlobalState`. |
| `history_list` / `history_clear` / `history_delete` | SQLite history CRUD. Only `saved = 1` and currently-`running` scans are surfaced; unsaved rows are purged at app launch. |
| `history_set_saved` | Flip the `saved` flag on a `scans` row so it survives the next-launch auto-purge. Backs the Dashboard's *Save scan* button. |
| `history_findings` | Return every persisted finding for a past scan from the `scan_findings` table. Drives the History view's inline-expand row that re-renders the full FindingsTable for a historical run. |

### VulnDB / probe / fingerprints

| Command | What it does |
| --- | --- |
| `vulndb_summary` / `vulndb_update` | NVD+EPSS vulnerability DB inspector + refresher (daily / full mode). |
| `sonar_summary` | Inventory of scripted/static probes + fingerprint sets, with user-supplied extra files merged in. |
| `device_db_summary` | Roll-up for the embedded `devices.sqlite` SNMP catalog — entry / vendor / device-type / clause counts; sysObjectID-prefix, sysDescr-substring, sysDescr-regex totals; and IANA Private Enterprise Number + IEEE OUI row counts read from the same SQLite file. Backs the Databases → *Device signatures* tab. Returns `catalog_ready: false` (with zero counts) when no signature catalog is loaded so the tab can render a build-instruction state instead of erroring. |
| `nuclei_summary` / `nuclei_template_list` / `nuclei_extras_download` / `nuclei_extras_remove` | Nuclei bundle inspector + tier-2 cache management. |
| `wappalyzer_summary` | Fingerprint dataset (embedded + seed). |
| `jarm_lookup` | Decompose a JARM hash into cipher/version + extensions digest and look up known matches. |
| `probe_start` / `probe_cancel` | Standalone service probing (target expansion, per-host concurrency, live events). `ProbeParams` carries `snmp_fingerprint` and `mac_lookup` toggles (Deep mode treats both as true regardless of the input flag). |

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
| `asset_endpoints_clustered` | Re-aggregates `asset_endpoints` over endpoint patterns (`/api/users/:id`) for the asset Endpoints panel's `[Clustered]` toggle. |

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
| `exchanges_clustered_list` | Pattern-clustered roll-up of the session's exchanges, with one row per `(method, host, port, pattern)` plus running anomaly badges (`AuthMismatch`, `StatusOutlier`, `SizeOutlier`, `RateLimited`). Backs the Traffic tab's *Group by endpoint* view. |
| `cluster_instances` | Lazy-load the member exchanges of a cluster row by re-deriving the pattern over `exchanges_list` results. |
| `intercept_set_mode` / `intercept_get_mode` / `intercept_pending_list` / `intercept_resolve` / `intercept_drop_all` | Intercept queue control (applies to both request and response phases). |
| `intercept_rules_get` / `intercept_rules_set` | Conditional intercept-rule CRUD. Rules narrow what the current intercept mode pauses on; conditions are AND-ed inside a rule, OR-ed across rules of the same kind, and exclude wins. Regex conditions are validated up-front; malformed rules are rejected at Save time. |
| `replay_send` | Re-send a stored request with optional raw-byte edit. The result is persisted as a new exchange under origin `Replay{parent}` and broadcast. |
| `checks_list` / `findings_for_exchange` / `findings_for_session` / `checks_run` | Checks engine descriptors, per-exchange and per-session findings, on-demand active check runs. Descriptor rows carry their resolved OWASP category label + description from the active `top10.yaml`. |
| `owasp_taxonomy_info` | Version, release, source, and full category list for the active `top10.yaml`. |

### CSRF token store

| Command | What it does |
| --- | --- |
| `csrf_rules_get` / `csrf_rules_set` | CRUD for the CSRF rule list — each rule pairs a `TokenSource` (`HtmlInput` / `MetaTag` / `JsonPath` / `SetCookie` / `ResponseHeader`) with a `TokenInject` (`FormField` / `JsonField` / `Header` / `Cookie`). |
| `csrf_rules_reset_defaults` | Restore the six bundled defaults (Laravel `_token`, Rails `authenticity_token` form + meta, ASP.NET `__RequestVerificationToken`, Django `csrfmiddlewaretoken`, Angular `XSRF-TOKEN` cookie). |
| `csrf_status` | Snapshot of the live token store — per `(rule, host)` it returns the latest observed value (truncated for display) and how long ago it was seen. |
| `csrf_clear_session` | Drop all observed tokens for the current session (rules are kept). Useful after logging in as a different user. |

### Exploit-DB

| Command | What it does |
| --- | --- |
| `exploitdb_summary` | Snapshot stats — total / verified row counts, by-type and top-platform breakdowns, origin (`bundled` / `user-synced`), upstream commit SHA, last refresh timestamp. |
| `exploitdb_by_cve` | Look up exploits by CVE ID. Case-insensitive; sorted verified DESC, date DESC. Backs every "Public exploits" row in Findings, SCA, and Asset findings. |
| `exploitdb_update` | Sync from `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` with `ETag`/`If-None-Match` short-circuiting. Emits `exploitdb://progress` events; replaces all rows in one transaction. |
| `exploitdb_fetch_source` | Download an exploit's raw source from GitLab and cache it on disk. Returns body + language hint for the in-UI source viewer. |

### Unified rules catalog

| Command | What it does |
| --- | --- |
| `rules_summary` | Inspect the embedded `rules.sqlite` catalog. Returns the resolved on-disk path (cwd > exe-dir > extracted blob), schema version, builder timestamp, pinned `nikto_commit` / `zap_commit` / `burp_commit` SHAs, per-source ingested vs executable counts (rules with non-NULL `match_spec_json` are runnable by `RulesPlugin`), per-(source, severity) breakdown, and a `json_valid()` integrity counter. Returns `{ loaded: false }` rather than erroring when no catalog is found, so the Databases tab can render a build instruction instead of a stack trace. |

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
- `probe://{id}/device-match` — SNMP device-fingerprint hit for a host (vendor, OS, device-type, source attribution `sysObjectID` / `sysDescr` / `fallback`, and the raw `sysDescr` / `sysObjectID` values that triggered the match). Drives the Probing run table's per-host Device chip and the Asset detail Device panel. Fires only when SNMP fingerprinting is enabled (always on in Deep mode; opt-in in Rapid).
- `probe://{id}/mac-resolved` — MAC-address observation for a host from the OS ARP / NDP cache, with the IEEE OUI vendor name resolved through `devices.sqlite`. Fires only when MAC capture is enabled (Deep mode default; opt-in in Rapid). Routed targets surface the upstream router's MAC; only L2-adjacent hosts return useful data.
- `recon://event` — single multiplexed channel keyed by `run_id`. Event kinds: `source_started`, `source_finished`, `wildcard_detected`, `subdomain_discovered`, `record_discovered`, `zone_transfer`, `brute_progress`, `complete`, `failed`, `cancelled`.
- `proxy://exchange-new` — every captured HTTP exchange (summary).
- `proxy://ws-frame` — every captured WebSocket frame (exchange id, sequence, direction, opcode, FIN flag, base64 payload).
- `proxy://intercept-pending` — new item parked on the intercept queue (request or response phase).
- `proxy://scan-finding` — passive or active Check finding for a captured exchange (also fires for cluster anomaly findings the first time each `(method, host, port, pattern, kind)` flag flips on).
- `proxy://csrf-observed` — fresh CSRF token harvested from a response (rule id, host, truncated value, observed-at). Drives the Settings → CSRF tokens live status panel.
- `exploitdb://progress` — Exploit-DB sync stages (`start`, `download`, `up_to_date`, `commit_lookup`, `parse`, `done`).
- `nuclei://progress` — Nuclei tier-2 download progress (when extras download is in flight).
- `app://init-step` — splash-screen progress: one event per init-step transition (`Pending` → `Running` → `Ok` / `Failed`) for each of the six first-launch steps (Recon DB, Exploit-DB index, Scan history, Probe store, Asset DB, Proxy state & CA). The frontend's SplashScreen subscribes to these so the user sees real progress instead of a frozen window during CA generation / DB seeding.
- `app://init-ready` — terminal splash event. Fired once every init step has reported its final state (success or failure). The SplashScreen unmounts and the main React tree mounts on this signal.
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
| `history.sqlite` | Scan history table (`scans` — with the `saved` flag for opt-in retention; unsaved rows are purged at next launch); per-scan persisted findings (`scan_findings`, `ON DELETE CASCADE` from `scans` so the History view's inline-expand can re-render past runs); proxy sessions, exchanges, WebSocket frames, scope rules, retention setting, intercept mode, key/value settings, findings; recon runs and recon findings (`recon_runs` + `recon_findings`, FK cascade); CSRF rules (`proxy_csrf_rules`); conditional intercept rules (`proxy_intercept_rules`, with conditions stored as a tagged-enum JSON blob to avoid future schema migrations); standalone-probe state (`probe_runs`, `probe_open_ports`, `probe_device_match` for SNMP-derived vendor / OS / device-type matches, `probe_host_mac` for OS-ARP MAC observations + IEEE OUI vendor names — all with `ON DELETE CASCADE` from `probe_runs`). WAL mode so every engine shares it safely. |
| `exploitdb.sqlite` | Exploit-DB snapshot — `exploits`, `exploit_cves`, `exploitdb_meta` tables. Seeded from a bundled snapshot on first launch and upgraded on app updates unless the user has run their own sync. Refreshable via the `exploitdb_update` command. |
| `proxy/ca/ca.cert.pem` + `proxy/ca/ca.key.pem` | Locally-generated Certificate Authority for HTTPS MITM. Regenerated on first proxy start if missing. |
| `proxy/bodies/<exchange-id>.{req,res}.bin` | Large request / response bodies that exceed the 512 KB inline cap are spilled here (up to the 32 MB per-side hard cap). Evicted alongside the parent exchange when retention trims. |
| `corvex/nuclei-templates/<tag>/` | Tier-2 Nuclei template cache (only `http/` is unpacked from the GitHub tarball). |
| `rules.sqlite` (extracted on first run, sibling of `history.sqlite`) | Embedded **unified rules catalog** consolidating Nikto + OWASP ZAP + Burp BCheck rules. The bytes are `include_bytes!`-baked into the desktop binary by `build.rs` and extracted on first launch (or after a binary upgrade — detected via length mismatch + first-4 KB compare). A cwd / exe-dir copy wins over the extracted blob so power users can swap catalogs without a rebuild. `RulesPlugin` opens this read-only at scan time. |
| `devices.sqlite` (extracted on first run, sibling of `history.sqlite`) | Embedded **SNMP device-signature catalog** — vendor / OS / device-type YAMLs lowered into matchable rows by `corvex-devicedb-builder`, plus the IANA Private Enterprise Numbers reference table and the IEEE OUI registry (MA-L / MA-M / MA-S). Same `include_bytes!` extraction shape as `rules.sqlite`: cwd > exe-dir > extracted blob, length + first-4 KB drift check on launch. Opened read-only by the probing engine and the `device_db_summary` command. |
| Bundled in binary | Web-signature DBs, Nuclei tier-1 curated templates, Wappalyzer seed + dataset, JARM known hashes, default config, OWASP `top10.yaml`, hidden-parameter wordlist, Wappalyzer → CPE map, Exploit-DB seed snapshot, default subdomain wordlist (~200 names), unified rules catalog (`rules.sqlite`, ~7 MB), SNMP device-signature catalog + IANA PEN + IEEE OUI tables (`devices.sqlite`), gzip-compressed NVD + EPSS snapshot (when present at build time — extracted to `<app_data_dir>/corvex/vulndb.sqlite` on first run). |

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

### 8.13 "Find an IDOR in /api/users/:id without scrolling 800 rows."

Intercept → Traffic → flip the chip to **Group by endpoint** → spot the
`/api/users/:id` cluster with an `AuthMismatch` or `StatusOutlier`
badge → expand the cluster, eyeball the differing instances → click
**Send to Fuzzer** on the cluster row. The Active Fuzzing form opens
with the pattern URL pre-filled and a seed banner showing the cluster
context plus the `PathSegment(usize)` injection hints — fuzz the `:id`
slot directly without hand-crafting per-segment positions. (Note: the
runner consumes the path-segment hints at the boundary; full
per-segment active-fuzz coverage is a follow-up — see §10.)

### 8.14 "Replay this CSRF-protected POST without getting a 419."

Intercept → Start → log into the target app in your browser. The CSRF
store auto-observes Laravel `_token`, Rails `authenticity_token`,
ASP.NET, Django, Angular, or any custom rule you've added — confirm
in **Settings → CSRF tokens** that the live status panel shows a
fresh observation. Pick the failing POST in Traffic → Send to Replay
→ leave **Apply CSRF** ticked → Send. The newest matching token is
swapped in before the request leaves and the exchange comes back
tagged `csrf-injected`. Active checks and the fuzzer route through
the same store, so SQLi / XSS / SSRF probes against the same endpoint
won't 419 either.

### 8.15 "Pause on first contact when a new subdomain comes online."

Recon → Run a recon job → on a row of interest click **Pause** (the
fourth row action). An Include intercept rule for that host
(HostGlob, request phase) is appended to **Settings → Intercept
rules**; the Intercept tab gains a `⚠ N rules active` chip. The next
time anything in your browser session touches that subdomain, the
request is queued in the Intercept tab for inspection — perfect for
catching whatever auth flow / hidden header the new host uses on
first contact. Drop the rule when you're done.

### 8.16 "Pivot through everything we know about this host."

Anywhere you see a crosshair `AssetLink` icon (Findings, Traffic, Recon
results, Probing rows, History) — click it. The Asset detail view
opens with eight panels (Identity / Device / Services / Stack /
Endpoints / Findings / Related / Timeline) drawn from a single
normalized host key. Switch to **Graph mode** for a radial overview, click a related
node (same JARM / same root domain / same /24) to recentre, and use
the breadcrumb stack (depth 8) to navigate back. Same target,
correlated across recon, probe, proxy, and dashboard scans, in one
place.

### 8.17 "Keep yesterday's scan but throw away the noise."

Run a quick exploratory scan from the Dashboard → glance at the
findings → close the tab. Nothing happens to History — the row sat in
`history.sqlite` with `saved = 0` and gets purged at the next launch.
Now run the scan you actually care about → click **Save scan** in the
FindingsTable toolbar → close the app. Tomorrow, open History: only
the saved run is there, with its full findings list one click away
through the inline-expand. No "Clear all" rituals, no janitor work —
**opt-in retention** keeps History for intentional records only.

### 8.18 "Re-read findings from a scan I ran two weeks ago."

History → expand any saved row by clicking its chevron. The view
fires `history_findings(id)` against the `scan_findings` table and
re-renders the full FindingsTable inline — same severity filters,
same JSON copy, same CVE-expand-to-Exploit-DB rows, same HTTP status
glossary tooltips. The lazy-load is cached per row so collapsing /
re-expanding is free. Pair with **Re-run** if you want to compare a
fresh run against the historical baseline.

### 8.19 "Identify what kind of device is sitting on a given IP."

Probing → enter the target → keep **Deep** mode (or stay on Rapid and
tick **SNMP device fingerprint** + **MAC address scan**) → Run. SNMP
fires in parallel with the TCP sweep against UDP/161 with community
`public`, asks for `sysObjectID.0` / `sysDescr.0`, and runs the
response through the bundled device catalog. A successful match
shows up in the run table as a per-host **Device** chip
(vendor + OS + device-type) and persists to `probe_device_match`.
Pair with the MAC pass — captured from the OS ARP / NDP cache and
resolved against the IEEE OUI table — for an L2-adjacency vendor
read where applicable. Click the host's `AssetLink` icon to land on
the Asset detail view; the new **Device** panel surfaces the
`sysDescr` / `sysObjectID` evidence and the MAC + OUI vendor
alongside the Identity / Services panels. Routed targets surface
the upstream router's MAC instead of the host's — documented on the
panel itself.

### 8.20 "Start a probe and keep working while it runs."

Probing → kick off a probe (`/24` of the target subnet, Deep mode,
SNMP + MAC on) → switch to Recon to plan tomorrow's enumeration, or
to the Asset view to pivot through what's already been discovered.
The probe keeps streaming results in the background — the
`ProbeRunningProvider` context owns the listener handles and result
tables above the view router, so navigation doesn't tear anything
down. Returning to Probing re-renders the live state with no replay
or refetch; the form inputs are still where you left them, the
Cancel button still works, and per-host Device / MAC chips have
been filling in while you were away.

### 8.21 "Confirm the unified rules catalog is loaded and healthy."

Databases → **Web signatures** tab (this surface used to be a
standalone *Unified rules* tab in v2.1; it's now the canonical Web
view because every web check flows through `RulesPlugin` against
this catalog). The header line shows whether `rules.sqlite` is
loaded (and from where — cwd, exe-dir, or the extracted-blob path
under app data), the schema version, and the builder timestamp. The
grid below it tabulates per-source ingested vs executable counts
(rules with non-NULL `match_spec_json` are runnable by `RulesPlugin`;
the percentage tells you how much of each upstream catalogue is
wired up), the pinned upstream commit SHAs for Nikto / ZAP / Burp,
and an invalid-JSON row counter that should always read `0` on a
healthy build. If the tab reports `loaded = false`, the desktop is
silently running on the legacy bincode path — rebuild the catalog
with
`cargo run -p corvex-rules-builder -- --sources rules-sources --output rules.sqlite`
and re-launch.

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

7. **Fully scriptable surface.** Every UI action maps to one of the 78
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
- XSS is reflected-only in v1 (both in the active injection engine and
  the Checks engine); DOM-based and stored XSS are planned.
- In the **active injection engine** (`FuzzingView.tsx` inventory),
  `file_upload`, `cms`, `tech`, `subdomain_takeover`, and `log4shell`
  are still marked **planned** — they have UI rows but aren't wired
  to runnable detectors. SSRF is handled by the **Checks engine**
  (`ssrf` active check) rather than the active injection engine.
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
- **Traffic clustering** — the `derive_pattern` heuristic is a segment
  classifier (`:id` / `:uuid` / `:oid` / `:slug`), not a learned model;
  unusual route shapes will under- or over-cluster. Anomaly badges
  (`AuthMismatch`, `StatusOutlier`, `SizeOutlier`, `RateLimited`) are
  *signals*, not proofs — treat them as triage prompts.
- **Path-segment fuzzing** is half-wired in v1: clusters surface
  `InjectionPoint::PathSegment(usize)` hints all the way to the
  `FuzzTarget::from_pattern_url` boundary and the Active Fuzz Runner
  shows the cluster seed banner, but the active runner does not yet
  iterate per-segment payloads — full per-segment injection in the
  runner is a follow-up.
- **CSRF rule shape** — form-field injection refuses to corrupt
  JSON bodies and vice-versa, and only the body content-types the
  rule's `TokenInject` is configured for are touched (multipart
  upload bodies, for instance, need a header- or cookie-shaped
  inject rule rather than form-field). Rules are global to the
  session; per-route overrides are not modelled in v1.
- **Conditional intercept rules** narrow what *pauses*, not what
  the proxy *captures*. Use Scope rules to control what's captured
  in the first place; intercept rules sit on top of the
  off/request/response/both mode selector and decide which captured
  exchanges are queued for inspection.
- **Unified rules catalog** is consumed in **side-by-side mode** by
  default — `RulesPlugin` (ZAP + Burp BChecks) and the legacy
  `TestsPlugin` (Nikto bincode) both run, with a manifest pre-emption
  layer so the same upstream rule doesn't fire twice. Full ownership
  flip to `RulesPlugin` is gated behind the CLI flag `--rules-only`
  for parity validation; the desktop has no UI toggle in v1.
  `match_spec_json` lowering coverage varies by source — check the
  Databases → Unified rules tab for the per-source executable %.
  When the embedded blob is the build placeholder (no
  `rules.sqlite` next to the workspace at compile time), the runtime
  falls back to legacy-only behaviour with a debug log; the user has
  no error to react to but loses the new BCheck / ZAP coverage.
- **Opt-in scan save** auto-purges any unsaved scan at the *next*
  launch, not at scan completion — exit the app without saving and
  the row stays through the rest of that session (so a mistake is
  recoverable until you close the window). Inline historical
  findings are persisted only for `scans` rows the user kept;
  unsaved rows take their `scan_findings` with them via
  `ON DELETE CASCADE`.
- **Splash screen** steps fail-soft individually but the proxy / CA
  step in particular is the slow one (RSA keygen on first launch).
  A failed step keeps its red badge and the rest of the app loads —
  but the affected subsystem will surface a more specific error on
  first user interaction (e.g. proxy listener won't start without a
  CA). Note: the splash gate covers the six heavy-init steps
  (Recon DB, Exploit-DB, History, Probe store, Asset DB, Proxy &
  CA); the **device-signature catalog** open is an in-line
  registration in `setup()` (it has no per-step splash badge), and
  the **vulndb warm-up** runs in the background after `setup()`
  returns — neither is visible on the splash. A failed device
  catalog open just leaves SNMP fingerprinting silently disabled.
- **SNMP device fingerprinting** uses SNMP v2c with community
  `public` and a small fixed timeout. Devices behind ACLs, or set
  up with `private`-only / SNMPv3, return nothing — the Device
  panel stays empty. The matcher is read-only: clauses that need an
  active follow-up GET (e.g. drilling into `ifTable` to confirm
  device class) are surfaced as the **disabled clauses** counter on
  the Databases → Device signatures tab and never fire at scan
  time. The catalog itself is community-curated and necessarily
  incomplete — empty Device panels for unknown vendors are normal.
- **MAC capture** reads the OS ARP / NDP cache after the TCP scan
  has already exchanged SYNs with the target — it does not send raw
  L2 frames or do its own ARP solicitations. As a consequence: only
  L2-adjacent hosts return a useful MAC; routed targets return the
  upstream router's MAC instead (documented in the Asset Device
  panel and the run-table chip). IPv6 NDP cache entries follow the
  same shape as IPv4 ARP entries on every supported platform.
- **Standalone probing's runner state lives in the React root**
  (`ProbeRunningProvider`). That keeps a probe alive across view
  navigations but means a full page reload (Cmd-R / Ctrl-R) drops
  the active run — there's no backend resume layer for standalone
  probes, only a persisted result trail in `probe_runs` /
  `probe_open_ports` / `probe_device_match` / `probe_host_mac`.
