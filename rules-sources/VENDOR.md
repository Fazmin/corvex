# Vendored rule sources

This directory holds the upstream rule data ingested by `corvex-rules-builder`
into a unified `rules.sqlite` catalog. Each subdirectory pins one upstream
project at a known commit so builds are reproducible and offline.

## Layout

```
rules-sources/
├── VENDOR.md            # this file
├── nikto/
│   └── db_tests         # canonical copy of program/databases/db_tests
├── zap/
│   ├── COMMIT           # upstream commit SHA
│   └── *.json           # extracted rule descriptors (see "Extraction" below)
└── burp/
    ├── COMMIT
    └── *.bcheck         # raw BCheck DSL files
```

## Sources

### Nikto — `nikto/db_tests`

- **Upstream**: https://github.com/sullo/nikto
- **License**: GPL-2.0
- **Format**: CSV-style flat file. 9 columns per row:
  `id, references, tuning, uri, method, dsl, message, data, headers`.
- **Vendoring policy**: Copied verbatim from the in-repo
  [program/databases/db_tests](../program/databases/db_tests). The builder reads
  this canonical copy so the location is independent of the legacy
  Perl-style layout and the build path can later be refactored.
- **Expected ingestion**: ~7,200 rules at ~100% success.

### OWASP ZAP — `zap/`

- **Upstream**: https://github.com/zaproxy/zap-extensions
- **License**: Apache 2.0
- **Format**: ZAP active and passive scan rules are implemented in Java; only
  *metadata* (rule ID, name, severity, confidence, CWE, references, payload
  arrays declared as static fields) is portable. The vendoring step extracts
  this metadata from the upstream Java sources and the addon
  `ZapAddOn.xml` files, then writes one JSON file per rule under this
  directory. The builder consumes those JSON descriptors.
- **Extraction**: When a real upstream snapshot is added, drop a `COMMIT`
  file naming the upstream commit SHA, and place one `<rule_id>.json` per
  rule in this directory. The builder reads every `*.json` here.
- **Expected ingestion**: depends on which addons are vendored. Typical
  active-scan addons hold ~50–150 rules.

### Burp Suite — `burp/`

- **Upstream**: https://github.com/PortSwigger/BChecks
- **License**: BCheck repository licenses vary per file — see the upstream
  README for the per-file attribution. Most community BChecks are
  permissively licensed.
- **Format**: BCheck files (`.bcheck`) — a small declarative DSL with
  `metadata { ... }` and `given/if/then` sections. The builder parses the
  metadata block and preserves the rest as opaque JSON for Phase 2.
- **Vendoring policy**: Drop pinned `.bcheck` files into this directory and
  record the upstream commit SHA in `burp/COMMIT`.
- **Expected ingestion**: depends on what's vendored; a representative
  community subset is ~50–100 rules.

## Adding or refreshing a source

1. Pull the upstream repo at the commit you want.
2. Copy the relevant files into the matching subdirectory.
3. Update or create the `COMMIT` file with the upstream SHA.
4. Run `corvex-rules-builder --sources rules-sources/ --output rules.sqlite`
   and check the report (`corvex-rules-builder --report rules.sqlite`) for
   per-source counts and skip reasons.

## Phase 1 status

Phase 1 of the unified-rules effort focuses on building the ingestion
pipeline. The builder is shipped here; what's vendored under `zap/` and
`burp/` at any given time is independent of the builder code. If those
directories are empty or missing, the builder simply reports zero rules
ingested for that source — useful as a smoke test of the framework
without committing third-party content.
