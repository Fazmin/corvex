# Third-party data — license notes

The bundled seed fingerprint set in [`src/fingerprint.rs`](../src/fingerprint.rs) is
written from first principles inside this repository. It intentionally
does not vendor any external dataset so the default build has no
redistribution obligations beyond the workspace license.

The fingerprint engine follows the **Wappalyzer technology schema**
(field layout: `categories`, `headers`, `cookies`, `html`, `meta`,
`url`, `implies`). Dropping an upstream dataset that follows that
schema into `data/wappalyzer/technologies/` will be picked up by the
runtime loader (lands in a follow-up) without further code changes.

## Attribution requirements for upstream drops

Before vendoring any external technology data, review the source's
license. At time of writing:

| Source | License | Notes |
|---|---|---|
| `AliasIO/wappalyzer` ≤ 6.10.x | MIT | Archived; redistribution with attribution OK. Include upstream `LICENSE` alongside vendored JSON. |
| `enthec/webappanalyzer` | GPL-3.0 | Strong-copyleft. **Not vendored** — linking GPL-3 into an MIT/Apache-2 codebase is typically inappropriate. Document decisions explicitly. |
| `projectdiscovery/wappalyzergo` | MIT | Ships Wappalyzer data as Go source; usable as a reference but re-serialise to JSON before vendoring. |
| `wappalyzer.com` (current) | Proprietary | Do not vendor. |

When adding upstream data:

1. Copy the raw JSON into `data/wappalyzer/` preserving its filename.
2. Copy the upstream `LICENSE` file into
   `data/wappalyzer/UPSTREAM_LICENSE.md`, with a leading note naming
   the project, version/tag, and commit SHA.
3. Update the table above with the date of the refresh.
4. Run the fingerprint tests — any schema shift between upstream
   versions surfaces as a regex compile or parser failure.

## Payload banks

`src/payloads.rs` ships a tiny hand-curated subset of XSS / redirect /
SQLi probes that was authored inside this repo. The Phase 3B plan's
full SecLists / FuzzDB / PayloadsAllTheThings vendoring follows the
same process — copy upstream `LICENSE` alongside the vendored data,
list the source here.
