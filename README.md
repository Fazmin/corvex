# Corvex

Corvex is a Rust web vulnerability scanner with two engines: a **signature engine** that probes targets against a 7,236-test database, and an **active fuzzing engine** that crawls the target, extracts forms and parameters, and injects payloads to detect injection vulnerabilities in real time. Built on `tokio` for concurrency and raw HTTP/1.x framing with direct OpenSSL handshakes for legacy TLS fingerprinting.

## What it does

### Signature engine (passive)

- Probes a target with Corvex's full signature database (7,236 tests + 1,257 outdated-software fingerprints + 362 favicon hashes + 260 server-banner rules + 170 auth realms + 40 404-page signatures + 1,825 dictionary entries).
- Expands `@LFI(nix|win|abs|url)` for local-file-inclusion tests, plus `@JUNK(n)`, `@IP`, `@HOSTNAME`, and every variable from `db_variables` (`@CGIDIRS`, `@USERS`, `@ADMIN`, ...).
- Runs 25 scan plugins: shellshock (CVE-2014-6271), Spring Boot actuator enumeration, Optionsbleed (CVE-2017-9798), MS10-070 ASP.NET padding oracle, PUT/DELETE verification, mod_userdir enumeration, mod_negotiation detection, exposed site files (`.git/`, `.env`, `backup.*`, `WEB-INF/`, ...), CGI directory probing, favicon fingerprinting, robots.txt harvesting, HTML path extraction, cookie leak analysis, HTTP auth realm matching with default-credential lookup, and the full `db_tests` runner.
- Extracts TLS certificate subject, issuer, SAN, cipher, and protocol on the initial HTTPS handshake and surfaces them as findings.

### Active fuzzing engine

- **HTML crawler** with BFS link following, respecting scope (domain / subdomains / folder / page), configurable depth (`--crawl-depth`) and URL cap (`--max-urls`). Skips non-HTML responses and soft-404 pages.
- **Form extractor** parses every `<form>` on discovered pages, collecting method, action, and all input/select/textarea fields with their types and default values.
- **Injection-point framework** turns crawled URLs + forms into `FuzzTarget`s with typed `InjectionPoint`s (query param, POST body field, header, cookie, path segment). The `FuzzRunner` iterates one-parameter-at-a-time, sending mutated requests through the same `nfetch` pipeline so cookies, auth, evasion, and cancellation all work uniformly.
- **Active plugin suite** (Phase 2+, in progress): reflected XSS, error/boolean/time-based SQL injection, active LFI, command injection, CRLF injection, open redirect, XXE, SSTI, SSRF, stored XSS, file upload, Log4Shell, Spring4Shell, CMS fingerprinting (WordPress/Drupal/Joomla), technology detection, and subdomain takeover.
- Active fuzzing is **opt-in** via `--active` or `-Tuning g`. The default `@@DEFAULT` profile stays signature-only so existing workflows are unaffected.

### Shared infrastructure

- Supports Basic, Digest (RFC 2617, qop=auth), and NTLM Type-1 HTTP authentication.
- Loads user-supplied test databases at runtime via `-Userdbs`.
- Emits scan results as text, CSV, JSON, XML, HTML (using placeholder templates), or SQL.
- **Tauri v2 desktop app** with a React + TypeScript frontend, live findings streaming, collapsible sidebar, light/dark/system theme, configurable font size, scan history persisted in SQLite, and full plugin/database/settings views.

## Quick start

```bash
git clone https://github.com/fazminnizam/corvex
cd corvex
cargo build --release

# Signature-only scan (default)
./target/release/corvex --host http://www.example.com

# Active scan with crawler + injection fuzzers
./target/release/corvex --host http://www.example.com --active --scope domain
```

Prebuilt OpenSSL is not required — the workspace enables the `vendored` feature and builds OpenSSL from source. On Windows, this needs Strawberry Perl and NASM on `PATH`; on Linux/macOS, a C toolchain is enough.

## Desktop app

```bash
cargo install tauri-cli --version '^2'
cd crates/corvex-desktop/ui && npm install && cd ../../..
cargo tauri dev --manifest-path crates/corvex-desktop/Cargo.toml
```

Features: frameless window with custom titlebar, collapsible sidebar with SVG icons, live findings table (click to expand details), four stat cards with percentile meters and info tooltips, tracing log panel, scan history in SQLite, settings page with theme and font size controls.

## Crate layout

Four-crate Cargo workspace:

- [crates/corvex-core](crates/corvex-core) — engine library: config, CLI, HTTP client, TLS, DSL parser + evaluator, variable expansion, crawler, form extractor, fuzzer framework, scope filter, scan loop, plugin trait, report trait, target resolution, tuning / mutate / evasion.
- [crates/corvex-plugins](crates/corvex-plugins) — 25 scan plugins + 6 report sinks.
- [crates/corvex](crates/corvex) — the `corvex` CLI binary.
- [crates/corvex-desktop](crates/corvex-desktop) — Tauri v2 desktop GUI.

The 14 database files under [program/databases](program/databases) are compiled at build time into a single `bincode` blob and embedded via `include_bytes!`. The binary is self-contained.

## CLI flags

### Signature engine

| Flag | Purpose |
| --- | --- |
| `-host`, `-url` | Target host or URL |
| `-port` | One or more ports, comma-separated |
| `-ssl`, `-nossl` | Force SSL on/off |
| `-Tuning` | Filter tests by category (see below) |
| `-Plugins` | Plugin selector (`@@ALL`, `@@DEFAULT`, `-robots`, ...) |
| `-Format` | Output format(s): `txt`, `csv`, `json`, `htm`, `xml`, `sql` |
| `-output` | Write the report to this file |
| `-evasion` | IDS evasion transforms `1`-`9`, `A` |
| `-Add-header` | Extra request header, repeatable |
| `-id` | HTTP auth `user:pass[:realm]` (Basic / Digest / NTLM) |
| `-Userdbs` | Merge an additional user test CSV |
| `-useproxy` | Proxy URL override |
| `-404string` / `-404code` | Custom 404 heuristic |
| `-vhost` | Virtual host header |
| `-useragent` | Custom User-Agent |
| `-timeout`, `-Pause`, `-maxtime` | Time limits |
| `--max-concurrent-requests` | In-flight request cap |
| `--max-concurrent-hosts` | Parallel host cap |
| `--dbcheck` | Print database row counts |
| `--list-plugins` | Print plugin registry |
| `--Version` | Print version |

### Active fuzzing engine

| Flag | Purpose |
| --- | --- |
| `--active` | Enable active fuzzing (implies `--crawl`) |
| `--crawl` | Enable the HTML crawler |
| `--crawl-depth N` | Max link-following depth (default 3) |
| `--max-urls N` | Hard cap on crawled URLs (default 500) |
| `--scope` | `domain`, `subdomains`, `folder`, or `page` |
| `--exclude-pattern` | Exclude URLs matching this regex (repeatable) |
| `--openapi FILE` | Seed the crawl from an OpenAPI / Swagger spec |
| `--form-login URL` | POST to this URL to obtain a session cookie |
| `--form-login-data KV` | Form login body pairs (repeatable) |
| `--cookie-jar FILE` | Import Chrome / Firefox SQLite cookie DB |
| `--resume ID` | Resume a suspended scan session |
| `--oast URL` | Out-of-band callback host for blind detection |

Run `corvex --Help` for the complete list.

## Examples

```bash
# Signature scan with software-ID tuning, JSON output
corvex --host http://example.com -Tuning b -Format json --output scan.json

# Active scan: crawl + fuzz with domain scope
corvex --host http://example.com --active --scope domain --crawl-depth 4

# Active scan seeded from an OpenAPI spec
corvex --host http://api.example.com --active --openapi ./openapi.json

# Authenticated scan with form login
corvex --host http://example.com --active --scope folder \
  --form-login http://example.com/login \
  --form-login-data 'user=admin' --form-login-data 'pass=secret'

# Signature + active combined, HTML report
corvex --host http://example.com --active --scope domain -Tuning bg -Format htm --output report.html

# Import browser cookies for an authenticated scan
corvex --host http://internal.example.com --active --cookie-jar ~/cookies.sqlite
```

## DSL

Corvex's test database matches responses with a tiny DSL:

- `CODE:` / `!CODE:` — match or negate HTTP status codes (regex).
- `BODY:` / `!BODY:` — match or negate a regex against the response body.
- `HEADER:` / `!HEADER:` — match or negate `name:value` against response headers.
- `COOKIE:` / `!COOKIE:` — match or negate a stored cookie value.
- `@LFI()` — placeholder expanded at runtime into `(BODY:<nix-canary>|BODY:<win-canary>)`.
- `&&` joins matchers (logical AND). Regex alternation (`|`) and `(?i)` work inside each pattern.

## Tuning categories

| Code | Category |
| --- | --- |
| `0` | File Upload |
| `1` | Interesting File / Seen in logs |
| `2` | Misconfiguration / Default File |
| `3` | Information Disclosure |
| `4` | Injection (XSS / Script / HTML) |
| `5` | Remote File Retrieval — Inside Web Root |
| `6` | Denial of Service |
| `7` | Remote File Retrieval — Server Wide |
| `8` | Command Execution / Remote Shell |
| `9` | SQL Injection |
| `a` | Authentication Bypass |
| `b` | Software Identification |
| `c` | Remote Source Inclusion |
| `d` | WebService |
| `e` | Administrative Console |
| `g` | Active fuzzing (crawler + injection probes) |
| `x` | Invert (include everything except the rest) |

## Architecture

- **HTTP**: direct TCP via `tokio::net::TcpStream`, HTTP/1.x framed by hand. TLS via `openssl::ssl::SslConnector` with `SECLEVEL=0` and `ALL` ciphers for legacy fingerprinting.
- **TLS metadata**: `SslInfo` captured from the live handshake (cipher, protocol, cert chain). Stored on the per-host `Mark` and surfaced by the `ssl` plugin.
- **Plugins**: compile-time `Plugin` trait with six hook points (`Start`, `Recon`, `Scan`, `Prefetch`, `Postfetch`, `Active`). Ascending weight order per hook.
- **Active engine**: the `Active` hook runs after `Scan`. The crawler produces a `CrawlGraph` of discovered pages + forms. Each active plugin receives the graph and drives a `FuzzRunner` that iterates injection points one parameter at a time.
- **Scope**: `ScopeFilter` constrains the crawler and active plugins to the target domain, subdomains, folder, or page. `--exclude-pattern` regex blocklists layer on top.
- **Form extraction**: `scraper`-based parser extracts `<form>` elements with all fields, producing `FormDescriptor`s that the fuzzer framework converts into `FuzzTarget`s with typed `InjectionPoint`s.
- **Authentication**: Basic, Digest (RFC 2617, qop=auth), NTLM Type-1. Form-based auth via `--form-login`.
- **Databases**: 14 CSV files compiled to bincode at build time. User DBs merged at runtime via `-Userdbs`.
- **Concurrency**: `tokio` runtime. Multiple hosts in parallel; per-host semaphore for in-flight requests.
- **Reports**: `ReportSink` trait with text, CSV, JSON, XML, HTML (template-based), and SQL implementations.
- **Desktop**: Tauri v2 + React. `TauriEventSink` streams findings live. SQLite history. Tracing log bridge. Settings (theme + font size).

## Developing

```bash
cargo check --workspace
cargo build --workspace --release
cargo test --workspace     # 21 tests currently passing

./target/debug/corvex --dbcheck
./target/debug/corvex --list-plugins
./target/debug/corvex --Version
```

Environment:

- `RUST_LOG=corvex_core=debug,tests_plugin=info` for per-plugin tracing.
- `OPENSSL_NO_VENDOR=1` to use system OpenSSL instead of the vendored build.

## Authorized use only

This tool is intended for use in environments where you have explicit permission to test. Running it against servers you do not own or operate without written authorization is illegal in most jurisdictions. You assume all responsibility for how you use it.

## License

Copyright (c) 2026 Fazmin Nizam. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. The full license text is available at https://www.gnu.org/licenses/gpl-3.0.txt.
