# corvex

Corvex is a Rust web server vulnerability scanner. It probes HTTP/1.x targets with a large signature database, a plugin-driven scan pipeline, and direct OpenSSL handshakes for legacy TLS fingerprinting. Built on `tokio` for concurrency and `hyper`-free raw HTTP framing so the scanner can send non-standard methods, keep raw paths, and inject malformed bytes on the wire.

## What it does

- Probes a target web server with Corvex's full signature database (7,236 tests + 1,257 outdated-software fingerprints + 362 favicon hashes + 260 server-banner rules + 170 auth realms + 40 404-page signatures + 1,825 dictionary entries).
- Expands Corvex's full `@LFI(nix|win|abs|url)` template family for local-file-inclusion tests, plus `@JUNK(n)`, `@IP`, `@HOSTNAME`, and every variable from `db_variables` (`@CGIDIRS`, `@USERS`, `@ADMIN`, …).
- Runs a full plugin suite: shellshock (CVE-2014-6271), Spring Boot actuator enumeration, Optionsbleed (CVE-2017-9798), MS10-070 ASP.NET padding oracle, PUT/DELETE verification, mod_userdir enumeration, mod_negotiation detection, exposed site files (`.git/`, `.env`, `backup.*`, `WEB-INF/`, …), CGI directory probing, favicon fingerprinting, robots.txt harvesting, HTML path extraction, cookie leak analysis, HTTP auth realm matching with default-credential lookup, and the full `db_tests` test runner.
- Extracts TLS certificate subject, issuer, SAN, cipher, and protocol on the initial HTTPS handshake and surfaces them as findings.
- Supports Basic, Digest (RFC 2617, qop=auth), and NTLM Type-1 HTTP authentication.
- Loads user-supplied test databases at runtime via `-Userdbs`.
- Emits scan results as text, CSV, JSON, XML, HTML, or SQL.

## Quick start

```bash
git clone https://github.com/fazminnizam/corvex
cd corvex
cargo build --release

./target/release/corvex --host http://www.example.com
```

Prebuilt OpenSSL is not required — the workspace enables the `vendored` feature and builds OpenSSL from source. On Windows, this needs Strawberry Perl and NASM on `PATH`; on Linux/macOS, a C toolchain is enough.

## Crate layout

Corvex is a three-crate Cargo workspace:

- [crates/corvex-core](crates/corvex-core) — engine library: config, CLI model, HTTP client, TLS, DSL parser + evaluator, variable expansion, scan loop, plugin trait, report trait, target resolution, tuning / mutate / evasion.
- [crates/corvex-plugins](crates/corvex-plugins) — every scan plugin (one file per `corvex_*.plugin`) plus the six report sinks under [crates/corvex-plugins/src/report](crates/corvex-plugins/src/report).
- [crates/corvex](crates/corvex) — the thin `corvex` binary that wires `corvex-core` and `corvex-plugins` together.

The 14 database files under [program/databases](program/databases) are read once at **build time** by [crates/corvex-core/build.rs](crates/corvex-core/build.rs), serialized with `bincode`, and embedded into the binary via `include_bytes!`. The binary is self-contained — no external files required to run.

## Running

```bash
# Text report to stdout
corvex --host http://example.com

# JSON report to a file, with only the "Software Identification" tuning category
corvex --host http://example.com -Tuning b -Format json --output scan.json

# HTML report
corvex --host http://example.com -Format htm --output scan.html

# Scan IPv4 only, no DNS lookup, 16 parallel in-flight requests per host
corvex --host 10.0.0.5 -ipv4 --nolookup --max-concurrent-requests 16

# Run against HTTPS and force a cipher-permissive handshake
corvex --host https://legacy.example.com --ssl

# Multiple targets, multiple report formats simultaneously
corvex --host host1,host2,host3 -Format txt,json,html --output report

# HTTP authentication — Basic, Digest, or NTLM (auto-detected from challenge)
corvex --host https://internal.example.com -id admin:s3cret

# Merge a custom user test database on top of the shipped signatures
corvex --host http://example.com -Userdbs ./udb_tests

# Run only a subset of plugins
corvex --host http://example.com -Plugins "@@DEFAULT;-tests;shellshock;springboot"
```

### CLI flags

Common flags:

| Flag | Purpose |
| --- | --- |
| `-host`, `-url` | Target host or URL |
| `-port` | One or more ports, comma-separated |
| `-ssl`, `-nossl` | Force SSL on/off |
| `-Tuning` | Filter tests by category (see below) |
| `-Plugins` | Plugin selector (`@@ALL`, `@@DEFAULT`, `-robots`, …) |
| `-Format` | Output format(s): `txt`, `csv`, `json`, `htm`, `xml`, `sql` |
| `-output` | Write the report to this file |
| `-evasion` | IDS evasion transforms `1`–`9`, `A` |
| `-Add-header` | Extra request header, repeatable |
| `-id` | HTTP auth `user:pass[:realm]` — scheme chosen from the `WWW-Authenticate` challenge (Basic / Digest / NTLM) |
| `-Userdbs` | Merge an additional user test CSV on top of the embedded database |
| `-useproxy` | Proxy URL override |
| `-404string` / `-404code` | Force a custom 404 heuristic |
| `-vhost` | Virtual host header |
| `-useragent` | Custom User-Agent |
| `-timeout`, `-Pause`, `-maxtime` | Per-request, inter-request, per-host time limits |
| `--max-concurrent-requests` | In-flight request cap |
| `--max-concurrent-hosts` | Parallel host cap |
| `--dbcheck` | Load every database and print row counts |
| `--list-plugins` | Print the plugin registry |
| `--Version` | Print version and exit |

Run `corvex --Help` for the complete list.

## DSL

Corvex's test database matches responses with a tiny DSL:

- `CODE:` / `!CODE:` — match or negate HTTP status codes (regex).
- `BODY:` / `!BODY:` — match or negate a regex against the response body.
- `HEADER:` / `!HEADER:` — match or negate `name:value` against response headers.
- `COOKIE:` / `!COOKIE:` — match or negate a stored cookie value.
- `@LFI()` — placeholder expanded at runtime into `(BODY:<nix-canary>|BODY:<win-canary>)` using `@LFIMATCHNIX` / `@LFIMATCHWIN` from `db_variables`.
- `&&` joins matchers (logical AND). Regex alternation (`|`) and case-insensitive flags (`(?i)`) work inside each matcher's pattern.

Example:

```
CODE:200&&BODY:phpinfo\(\)&&!HEADER:x-powered-by:cloudflare
```

## Template variables

Test URIs and payloads are expanded through a variable engine that fans out into every concrete candidate before the request is sent:

| Variable | Source | Semantics |
| --- | --- | --- |
| `@IP`, `@HOSTNAME`, `@PORT` | target `Mark` | single scalar substitution |
| `@JUNK(n)` | runtime | n random alphanumeric bytes |
| `@LFI(...)` | `db_variables` | see below |
| `@CGIDIRS`, `@ADMIN`, `@USERS`, `@PASSWORDFILES`, `@PHPMYADMIN`, … | `db_variables` | fan out — one test per value |

`@LFI(...)` accepts any combination of `nix`, `win`, `abs`, `url`:

- `nix` / `win` — target that platform (omit both to follow the server's detected platform).
- `abs` — use the absolute target path (`/etc/hosts`, `\Windows\win.ini`) with no traversal.
- `url` — percent-encode the final path.

Depth and target paths come from `@LFIDEPTH`, `@LFITGTNIX`, `@LFITGTWIN`, `@LFIPATHNIX`, `@LFIPATHWIN` in [program/databases/db_variables](program/databases/db_variables). On a target with an unknown platform, `@LFI()` fans out into both the nix and the win payload, so a single test row becomes two in-flight requests.

## Plugins

Corvex ships 25 scan plugins and 6 report sinks, all statically registered at startup. Selection uses the `-Plugins` selector syntax (`@@ALL`, `@@DEFAULT`, `@@EXTRAS`, comma/semicolon lists, `-name` to exclude).

**Scan plugins**

| Plugin | Hook | Purpose |
| --- | --- | --- |
| `tests` | Scan (99) | Runs the full `db_tests` signature database with DSL evaluation, variable fan-out, and evasion transforms |
| `headers` | Postfetch (20) | Reports missing recommended security headers from `db_headers_suggested` |
| `outdated` | Postfetch (30) | Matches `Server:` banner against `db_outdated` |
| `msgs` | Postfetch (35) | Matches server banner against `db_server_msgs` |
| `auth` | Postfetch (40) | Parses `WWW-Authenticate`, matches realm against `db_realms`, surfaces default credentials |
| `content_search` | Postfetch (45) | Applies `db_content_search` regexes to every response body |
| `cookies` | Postfetch (50) | Detects internal IP addresses leaked via `Set-Cookie` |
| `paths` | Postfetch (50) | Harvests `href` / `src` / `action` targets from the root page |
| `robots` | Recon (49) | Fetches `/robots.txt` and reports Disallow entries |
| `cgi` | Recon (50) | Probes every directory in `@CGIDIRS` |
| `favicon` | Recon (55) | MD5-matches `/favicon.ico` against `db_favicon` |
| `ssl` | Recon (10) | Surfaces cert subject / issuer / SAN / cipher / protocol captured during the initial TLS handshake |
| `options` | Scan (50) | Calls `OPTIONS /` and matches returned methods against `db_options` |
| `optionsbleed` | Scan (75) | CVE-2017-9798 probe via Allow-header drift + non-printable byte detection |
| `put_del_test` | Scan (65) | Attempts PUT → GET confirm → DELETE cleanup with a random test file |
| `multiple_index` | Scan (55) | Brute-forces `db_multiple_index` for overlapping default documents |
| `negotiate` | Scan (60) | Detects Apache mod_negotiation via `Content-Location` / `300 Multiple Choices` |
| `sitefiles` | Scan (60) | Probes 17 common leftover / backup / dev files (`.git/HEAD`, `.env`, `backup.*`, `WEB-INF/web.xml`, …) |
| `shellshock` | Scan (70) | CVE-2014-6271 via injected `User-Agent` / `Referer` / `Cookie` canary across 7 CGI endpoints |
| `springboot` | Scan (70) | Probes 14 Spring Boot actuator endpoints under `/` and `/actuator/` |
| `ms10_070` | Scan (70) | ASP.NET padding oracle on `/ScriptResource.axd` |
| `apacheusers` | Scan (60) | mod_userdir enumeration via `/~user/` for every name in `@USERS` |
| `fileops` | Postfetch (50) | Persists raw responses under `--Save` |
| `dictionary_attack` | Recon (20, extras) | Probes paths from `db_dictionary` |
| `siebel` | Scan (80, extras) | Siebel-specific checks |

**Report sinks** (`-Format`):

| Format | Notes |
| --- | --- |
| `txt` | Streaming plain text |
| `csv` | One finding per row, quoted and escaped |
| `json` | Structured document with scan summary + per-host findings |
| `xml` | `<corvexscan>` / `<scandetails>` / `<item>` |
| `htm` | Renders the placeholder templates from [program/templates/](program/templates/) — conditional SSL / Reference rows handled |
| `sql` | `INSERT` statements matching [documentation/corvex_schema_mysql.sql](documentation/corvex_schema_mysql.sql) / [postgresql](documentation/corvex_schema_postgresql.sql) |

## Tuning categories

Pass a string of category letters to `-Tuning` to restrict the test set. Add `x` to invert the selection.

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
| `x` | Invert (include everything except the rest) |

## Architecture notes

- **HTTP**: direct TCP via `tokio::net::TcpStream`, HTTP/1.x framed by hand so the scanner can send non-standard methods (`PROPFIND`, `SEARCH`, …), keep raw paths, and inject malformed bytes. TLS runs through `openssl::ssl::SslConnector` built directly with `SECLEVEL=0` and `ALL` ciphers — legacy SSLv3 / TLS 1.0 handshakes that `rustls` refuses still work here, which is the whole point of a fingerprinting scanner.
- **TLS metadata**: every HTTPS response carries an attached `SslInfo` struct populated from the live handshake — cipher, protocol version, cert subject, issuer, subjectAltName list, not-before / not-after. The scan loop stores it on the per-host `Mark` and the `ssl` plugin surfaces it to every report sink.
- **Plugins**: a compile-time `Plugin` trait with five hook points (`Start`, `Recon`, `Scan`, `Prefetch`, `Postfetch`). Plugins are statically registered at startup and iterated in ascending weight order per hook.
- **Authentication**: `http/auth.rs` implements Basic (trivial), Digest (RFC 2617 with `qop=auth`, nonce, cnonce, nc, opaque — MD5 algorithm), and NTLM Type-1 negotiation. The scheme is chosen from the server's `WWW-Authenticate` challenge.
- **Databases**: 14 CSV files are compiled once by `build.rs` into a single `bincode` blob. First access deserializes the blob into an `Arc<Databases>` shared across all scans. User databases passed via `-Userdbs` are parsed at runtime by the same schema through [crates/corvex-core/src/db/csv_loader.rs](crates/corvex-core/src/db/csv_loader.rs) and merged on top of the shipped rows.
- **Variable expansion**: `vars.rs` drives an iterate-until-stable expander that fans out each `@VAR` into every concrete candidate. `@LFI(...)` handles platform negotiation, traversal depth, absolute vs relative paths, URL encoding, and double-separator collapsing — plus `expand_lfi_dsl` for `@LFI()` tokens embedded in DSL matchers.
- **DSL**: the parser walks tokens with depth tracking for brackets so that `&&` inside a character class or group doesn't split the expression. Regexes compile through the `regex` crate.
- **Concurrency**: `tokio` runtime. Multiple hosts scan in parallel (`--max-concurrent-hosts`) and within each host a `Semaphore` caps the number of in-flight tests (`--max-concurrent-requests`).
- **Reports**: one `ReportSink` trait, six implementations (`text`, `csv`, `json`, `xml`, `html`, `sql`). The HTML sink loads the six placeholder templates from `program/templates/` at compile time (`include_str!`) and substitutes `#TEMPL_*#` markers per host / per finding, with conditional row handling for missing SSL or reference fields.

## Developing

```bash
# Fast iteration
cargo check --workspace

# Full build (vendored OpenSSL compile, one-time)
cargo build --workspace --release

# Unit tests: DSL parser, config, LFI variable expansion (6 cases), DB
# round-trip, Digest/NTLM auth header construction, and DSL operator
# coverage. Currently 15 tests across the workspace, all passing.
cargo test --workspace

# Smoke tests
./target/debug/corvex --dbcheck
./target/debug/corvex --list-plugins
./target/debug/corvex --Version
```

Environment knobs:

- Set `RUST_LOG=corvex_core=debug,tests_plugin=info` to see per-plugin progress.
- `OPENSSL_NO_VENDOR=1` switches to your system OpenSSL instead of the bundled build.

## Authorized use only

This tool is intended for use in environments where you have explicit permission to test. Running it against servers you do not own or operate without written authorization is illegal in most jurisdictions. You assume all responsibility for how you use it.

## License

Copyright © 2026 Fazmin Nizam. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. The full license text is available at https://www.gnu.org/licenses/gpl-3.0.txt.
