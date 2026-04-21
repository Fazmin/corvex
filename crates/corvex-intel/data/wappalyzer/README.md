# Vendored Wappalyzer dataset

This directory receives the contents of an upstream Wappalyzer
technology database. It is **empty by default** — corvex ships with
the small seed in [`src/fingerprint.rs`](../../src/fingerprint.rs) and
falls back to it whenever the files below are missing.

## Populate

From the repo root:

```bash
scripts/refresh-wappalyzer.sh              # latest main from HTTPArchive/wappalyzer
scripts/refresh-wappalyzer.sh <tag-or-sha> # pin to a specific ref
```

The script clones the upstream, copies the technologies JSON, drops a
verbatim `UPSTREAM_LICENSE.md` alongside, and runs the fingerprint
tests to catch any upstream schema drift.

## Expected layout

```
wappalyzer/
├── README.md               (this file)
├── UPSTREAM_LICENSE.md     (written by the refresh script)
├── categories.json         (Wappalyzer category map)
└── technologies/
    ├── a.json
    ├── b.json
    └── …
```

## At runtime

On first start, [`corvex_intel::fingerprint::load_dataset`](../../src/fingerprint.rs)
walks this directory. Every entry that parses cleanly becomes a
`LoadedFingerprint`; the Stack Fingerprint passive check runs the
loaded dataset first, then falls back to the compile-time seed for any
stack the upstream doesn't cover.

## License awareness

Do not vendor datasets whose license is incompatible with the
workspace license. See
[`../LICENSE_NOTES.md`](../LICENSE_NOTES.md) for the attribution table
and refresh protocol.
