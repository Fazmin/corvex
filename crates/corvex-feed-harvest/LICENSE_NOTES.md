# corvex-feed-harvest — licensing & policy

This crate is a **developer tool**. It is not built into `corvex` or
`corvex-desktop`, not exposed as a Tauri command, and not shipped to users.
Its sole purpose is to read the Greenbone OpenVAS Community Feed and emit
**scaffold stubs** for hand-authored rules under
`rules-sources/openvas-port/_scaffolds/`.

## Why this crate exists separately

The corvex-rust workspace and the OpenVAS Community Feed are both
GPL-2.0-only, so license compatibility is not the constraint. Provenance
hygiene is. Specifically:

1. **Each rule cites the exact vendor advisory it implements.** A reviewer
   can audit any finding back to a primary source without reading NASL.
2. **Detection bugs in the upstream feed do not ride along.** Our matcher
   is independently authored.
3. **Relicensing optionality.** If the project ever moves to a permissive
   license, no rule file has to be rewritten.

To preserve those properties the harvester is kept architecturally separate
from the runtime.

## Hard rules

- The harvester **may** rsync the OpenVAS feed into `program/feed-cache/`.
  That directory is `.gitignore`d and must never enter the repo.
- The harvester **may** parse `.nasl` files for **factual metadata only**:
  `script_oid`, `script_name`, `script_cve_id`, `script_bugtraq_id`,
  `script_xref`, `script_family`, `script_category`,
  `script_require_ports`, `script_cpe_match`, `script_dependencies`. Facts
  about a vulnerability (CVE IDs, CPEs, default ports) are not
  copyrightable expression.
- The `scaffold` subcommand **must not** copy `.nasl` body strings, regex
  literals, helper-function calls, or `description {}` blocks into
  scaffold files.
- The `transpile` subcommand **may** copy a single regex *literal* out of
  the NASL body into the emitted `MatchSpec`. The narrow exception is
  justified because:
  1. The transpiler runs only on VTs whose entire detection logic IS
     "match this regex against this banner / response body" — the regex
     is the fact, not creative expression. The same pattern would
     appear in the original vendor advisory (CVE record, vendor
     security bulletin) the NASL author copied it from.
  2. Workspace and feed both license under GPL-2.0-only, so even a
     stricter view of derivative work poses no compatibility issue.
  3. Transpiled rules carry `provenance.transpiled = true` so review
     and audit can distinguish them from hand-authored rules at a
     glance.
  Anything richer than a single regex literal — multi-step logic,
  conditional branches, helper-function calls — falls into hand-authoring.
- Scaffolds land under `rules-sources/openvas-port/_scaffolds/` and are
  **never ingested by `corvex-rules-builder`**. The parser at
  `crates/corvex-rules-builder/src/parsers/openvas_port.rs` skips that
  subtree by name.
- A human author re-expresses the detection in `MatchSpec` form against
  the **original vendor advisory** (NVD, vendor security bulletin, CISA
  KEV, etc.) — *not* against the NASL — and moves the file into a
  family-named folder under `rules-sources/openvas-port/`.

## Status

This crate is currently a stub. The full rsync wrapper, NASL metadata
parser, and NVD enrichment pipeline are scoped under Phase A of the
roadmap. The placeholder `main.rs` documents the intended CLI surface so
the wiring is in place.
