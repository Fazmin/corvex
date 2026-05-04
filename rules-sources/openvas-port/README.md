# `openvas-port` — hand-authored network/service rules

Each `*.json` file under this tree (outside `_scaffolds/`) is one detection
rule that the builder ingests as `source_tool = 'openvas-port'`. These rules
are **not** transpiled NASL. They are re-authored, by humans, against the
**original vendor advisory** for the underlying issue.

## Why hand-author when corvex-rust is GPL-2.0?

License-wise we could vendor `.nasl` files directly; the workspace and the
OpenVAS Community Feed are both GPL-2.0. We don't, on purpose:

- **Provenance hygiene.** Every rule cites the exact advisory it implements.
  A reviewer can audit any finding back to a primary source without reading
  NASL.
- **Bug-surface isolation.** Detection bugs in the upstream feed don't ride
  along into our catalog.
- **Relicensing optionality.** If the project ever moves to a permissive
  license, no rule has to be rewritten.

The dev-only `corvex-feed-harvest` tool reads the Community Feed *only as a
catalog of facts* (CVE / OID / CPE / default ports / family) to scaffold
stub files into `_scaffolds/`. A human moves them out and writes the
detection.

## File layout

```
rules-sources/openvas-port/
  _scaffolds/                  # dev-only stubs from corvex-feed-harvest;
                                 NEVER ingested by the builder.
  service/                     # service banner / version / config exposure
  cms/                         # WordPress, Drupal, Joomla, …
  appserver/                   # Tomcat, JBoss, WebLogic, …
  http-misc/                   # everything else
  network/                     # Phase C+ — TLS / TCP banner / SSH / SMB / …
```

Folder names are organisational — the parser walks recursively and the rule's
`category` field is what surfaces in the UI.

## Schema (one rule = one JSON file)

```jsonc
{
  "id": "corvex-net.apache-mod-status-exposed",
  "name": "Apache mod_status server-status page exposed",
  "description": "Detects an unrestricted /server-status page exposing live Apache request data.",
  "severity": "medium",                 // critical | high | medium | low | info
  "confidence": "high",                 // optional — high | medium | low
  "category": "info-disclosure",
  "owasp_2025": "A05",                  // optional
  "cwe": 16,                            // optional
  "references": [
    "https://httpd.apache.org/docs/current/mod/mod_status.html"
  ],

  // Pre-built MatchSpec, validated by the lowering pass. Required.
  "match_spec": {
    "steps": [
      {
        "id": "r0",
        "method": "GET",
        "uri": "/server-status",
        "headers": [],
        "body": null,
        "payload": null
      }
    ],
    "when": [
      { "matcher": { "kind": "status", "step": "r0", "regex": "^200$" } },
      { "matcher": { "kind": "body",   "step": "r0",
                     "regex": "Apache Server Status for" } }
    ]
  },

  // Provenance. All fields optional. For rules scaffolded from a NASL,
  // `openvas_oid` and at least one `advisory_urls` entry are mandatory at
  // PR-review time (not enforced by the parser).
  "provenance": {
    "advisory_urls": [
      "https://httpd.apache.org/docs/current/mod/mod_status.html"
    ],
    "default_ports": [80, 443, 8080],
    "cpe_match": ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"]
  }
}
```

## Authoring rules

1. **Scaffold (optional)** — run `corvex-feed-harvest scaffold --oid <OID>`
   to seed `_scaffolds/<oid>.json` with the harvested facts. Skip this if
   you're authoring a rule from scratch.
2. **Read the vendor advisory.** Not the NASL.
3. **Express the detection in `MatchSpec`.** Use status / body / header /
   cookie matchers. For multi-step detections, give each step a stable `id`
   and bind matchers to it.
4. **Move the file** out of `_scaffolds/` into the appropriate family
   folder. The builder ignores everything under `_scaffolds/`.
5. **Run the builder** — `cargo run -p corvex-rules-builder` — and check
   the per-source ingestion count and skip-reasons.

## What NOT to do

- Don't paste regex / strings from the original NASL into `match_spec`.
  Re-derive them from the advisory.
- Don't commit `.nasl` files anywhere in the tree.
- Don't put incomplete rules outside `_scaffolds/` — the builder will fail
  them as `openvas_port_missing_match_spec` and they'll show up in the
  build report.
