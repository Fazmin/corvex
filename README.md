# nikto-rust

A Rust port of the Nikto web server vulnerability scanner. Same tuned signature database, same CLI shape, new engine: `tokio` for concurrency, `hyper` for raw HTTP/1.x, `openssl` directly for legacy TLS fingerprinting.

## What it does

- Probes a target web server with Nikto's full signature database (7,236 tests + 1,257 outdated-software fingerprints + 362 favicon hashes + …).
- Reports misconfigurations, dangerous default files, stale server versions, exposed admin consoles, and the usual categories below.
- Emits the scan in text, CSV, JSON, XML, HTML or SQL.

## Quick start

```bash
git clone https://github.com/fazminnizam/nikto-rust
cd nikto-rust
cargo build --release

./target/release/nikto --host http://www.example.com
```

Prebuilt OpenSSL is not required — the workspace enables the `vendored` feature and builds OpenSSL from source. On Windows, this needs Strawberry Perl and NASM on `PATH`; on Linux/macOS, a C toolchain is enough.

## Crate layout

This is a three-crate Cargo workspace:

- [crates/nikto-core](crates/nikto-core) — engine library: config, CLI model, HTTP client, TLS, DSL parser + evaluator, variable expansion, scan loop, plugin trait, report trait, target resolution, tuning / mutate / evasion.
- [crates/nikto-plugins](crates/nikto-plugins) — every scan plugin (one file per `nikto_*.plugin`) plus the six report sinks under [crates/nikto-plugins/src/report](crates/nikto-plugins/src/report).
- [crates/nikto](crates/nikto) — the thin `nikto` binary that wires `nikto-core` and `nikto-plugins` together.

The 14 database files under [program/databases](program/databases) are read once at **build time** by [crates/nikto-core/build.rs](crates/nikto-core/build.rs), serialized with `bincode`, and embedded into the binary via `include_bytes!`. The binary is self-contained — no external files required to run.

## Running

```bash
# Text report to stdout
nikto --host http://example.com

# JSON report to a file, with only the "Software Identification" tuning category
nikto --host http://example.com -Tuning b -Format json --output scan.json

# Scan IPv4 only, no DNS lookup, 16 parallel in-flight requests per host
nikto --host 10.0.0.5 -ipv4 --nolookup --max-concurrent-requests 16

# Run against HTTPS and force a cipher-permissive handshake
nikto --host https://legacy.example.com --ssl

# Multiple targets, multiple report formats simultaneously
nikto --host host1,host2,host3 -Format txt,json,html --output report
```

### CLI flags

Every Perl-Nikto flag is preserved. Common ones:

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
| `-id` | Basic auth `user:pass[:realm]` |
| `-useproxy` | Proxy URL override |
| `-404string` / `-404code` | Force a custom 404 heuristic |
| `-vhost` | Virtual host header |
| `-useragent` | Custom User-Agent |
| `-timeout`, `-Pause`, `-maxtime` | Per-request, inter-request, per-host time limits |
| `--max-concurrent-requests` | In-flight request cap (Rust-port addition) |
| `--max-concurrent-hosts` | Parallel host cap (Rust-port addition) |
| `--dbcheck` | Load every database and print row counts |
| `--list-plugins` | Print the plugin registry |
| `--Version` | Print version and exit |

Run `nikto --Help` for the complete list.

## DSL

Nikto's test database matches responses with a tiny DSL. The Rust port implements the full operator set from the upstream docs:

- `CODE:` / `!CODE:` — match or negate HTTP status codes (regex).
- `BODY:` / `!BODY:` — match or negate a regex against the response body.
- `HEADER:` / `!HEADER:` — match or negate `name:value` against response headers.
- `COOKIE:` / `!COOKIE:` — match or negate a stored cookie value.
- `&&` joins matchers (logical AND). Regex alternation (`|`) and case-insensitive flags (`(?i)`) work inside each matcher's pattern.

Example (from the db_tests shipped in the signature DB):

```
CODE:200&&BODY:phpinfo\(\)&&!HEADER:x-powered-by:cloudflare
```

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

- **HTTP**: `hyper` at the client layer on top of `tokio::net::TcpStream`, with `openssl::ssl::SslConnector` constructed directly so the scanner can send non-standard methods (`PROPFIND`, `SEARCH`, …), keep raw paths, and negotiate legacy cipher suites (`SECLEVEL=0`, full `ALL` list) against old servers. Certificate chain, cipher, and protocol version are extracted for the `ssl` plugin.
- **Plugins**: a compile-time `Plugin` trait with five hook points (`Start`, `Recon`, `Scan`, `Prefetch`, `Postfetch`) that mirror Perl Nikto's lifecycle. Plugins are statically registered at startup and iterated in weight order per hook.
- **Databases**: 14 upstream CSV files are compiled once by `build.rs` into a single `bincode` blob. First access deserializes the blob through an `Arc<Databases>` shared across all scans. User databases passed via `-Userdbs` are parsed at runtime through the same schema.
- **DSL**: the parser walks tokens with depth tracking for brackets so that `&&` inside character classes doesn't split the expression. Regexes compile through the `regex` crate.
- **Concurrency**: `tokio` runtime. Multiple hosts scan in parallel (`--max-concurrent-hosts`) and within each host a `Semaphore` caps the number of in-flight tests (`--max-concurrent-requests`). The Perl original is serial — expect a significant speedup on high-latency targets.
- **Reports**: one `ReportSink` trait, six implementations (`text`, `csv`, `json`, `xml`, `html`, `sql`). `-Format txt,json,html` emits all three simultaneously.

## Developing

```bash
# Fast iteration
cargo check --workspace

# Full build (vendored OpenSSL compile, one-time)
cargo build --workspace --release

# Unit tests (DSL parser, config, variable expansion, DB round-trip)
cargo test --workspace

# Smoke tests
./target/debug/nikto --dbcheck
./target/debug/nikto --list-plugins
./target/debug/nikto --Version
```

Environment knobs:

- Set `RUST_LOG=nikto_core=debug,tests_plugin=info` to see per-plugin progress.
- `OPENSSL_NO_VENDOR=1` switches to your system OpenSSL instead of the bundled build.

## Authorized use only

This tool is intended for use in environments where you have explicit permission to test. Running it against servers you do not own or operate without written authorization is illegal in most jurisdictions. You assume all responsibility for how you use it.

## License

Copyright © 2026 Fazmin Nizam. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3, as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. The full license text is available at https://www.gnu.org/licenses/gpl-3.0.txt.

The signature databases under [program/databases](program/databases) are not licensed under the GPL and retain the distribution terms of the upstream Nikto project. They may only be distributed as part of this package, for use with this scanner.

LibWhisker is referenced for historical lineage — its license is preserved in [COPYING.LibWhisker](COPYING.LibWhisker).
