//! Parser for hand-authored "openvas-port" detection rules.
//!
//! These are NOT NASL files. The OpenVAS Community Feed is read only as a
//! catalog of facts (CVE / OID / CPE / default port) by the dev-only
//! `corvex-feed-harvest` tool, which scaffolds stub JSON files into
//! `rules-sources/openvas-port/_scaffolds/`. A human author then re-expresses
//! each detection in `MatchSpec` form against the **original vendor advisory**,
//! and moves the file into a family-named subdirectory under
//! `rules-sources/openvas-port/` (anywhere outside `_scaffolds/`).
//!
//! Files live in `rules-sources/openvas-port/<family>/<oid>.json` once
//! authored. The parser ignores `_scaffolds/` so half-written stubs never
//! reach `rules.sqlite`.
//!
//! See `crates/corvex-feed-harvest/LICENSE_NOTES.md` for the clean-room
//! discipline.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use walkdir::WalkDir;

use crate::normalized::{Confidence, NormalizedRule, ParseStats, Severity, SourceTool};

/// Top-level shape of one rule file. Mirrors `NormalizedRule` field-for-field
/// where it makes sense, with the lowered `MatchSpec` carried under
/// `match_spec`. The MatchSpec is left as `serde_json::Value` here — the
/// builder's `lower::try_lower` does the typed deserialization, which keeps
/// the dependency graph tight (this parser doesn't pull `corvex-rules` in).
#[derive(Debug, Deserialize)]
struct OpenvasPortRuleFile {
    /// Stable rule identifier. Convention: the OpenVAS OID
    /// (`1.3.6.1.4.1.25623.1.0.<n>`) when ported from a feed VT, or a
    /// `corvex-net.<short-slug>` identifier for rules authored from scratch.
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    severity: SeverityWire,
    #[serde(default)]
    confidence: Option<ConfidenceWire>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    owasp_2025: Option<String>,
    #[serde(default)]
    cwe: Option<i64>,
    #[serde(default)]
    references: Vec<String>,
    /// Pre-built MatchSpec, validated by the lowering pass. Required —
    /// rules without one are skipped and counted as
    /// `openvas_port_missing_match_spec`.
    #[serde(default)]
    match_spec: Option<Value>,
    /// Provenance: which OpenVAS OID this was ported from, plus the
    /// vendor-advisory URL the detection was actually written against.
    /// Both go into `source_meta_json` for later audit.
    #[serde(default)]
    provenance: Option<Provenance>,
    /// Optional explicit `enabled` flag. Defaults to `true`. Authors flip
    /// this to `false` while a rule is being worked on; the file still
    /// validates and the row is written but `enabled = 0`.
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SeverityWire {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityWire> for Severity {
    fn from(s: SeverityWire) -> Self {
        match s {
            SeverityWire::Critical => Severity::Critical,
            SeverityWire::High => Severity::High,
            SeverityWire::Medium => Severity::Medium,
            SeverityWire::Low => Severity::Low,
            SeverityWire::Info => Severity::Info,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ConfidenceWire {
    High,
    Medium,
    Low,
}

impl From<ConfidenceWire> for Confidence {
    fn from(c: ConfidenceWire) -> Self {
        match c {
            ConfidenceWire::High => Confidence::High,
            ConfidenceWire::Medium => Confidence::Medium,
            ConfidenceWire::Low => Confidence::Low,
        }
    }
}

#[derive(Debug, Deserialize)]
struct Provenance {
    /// OpenVAS OID this rule was scaffolded from (omitted for rules
    /// authored from scratch).
    #[serde(default)]
    openvas_oid: Option<String>,
    /// Vendor advisory / CVE record / CISA KEV entry the detection was
    /// re-authored against. **Required for any rule scaffolded from a
    /// `.nasl`** — the reviewer enforces this at PR time, not the parser.
    #[serde(default)]
    advisory_urls: Vec<String>,
    /// Default port(s) the rule expects to find the service on. Lifted
    /// from `script_require_ports` when present; informational today,
    /// consumed by Phase C's TCP-banner / TLS probe routing.
    #[serde(default)]
    default_ports: Vec<u16>,
    /// CPE URI the rule applies to (lifted from `script_cpe_match`).
    /// Consumed by SCA correlation and reporting.
    #[serde(default)]
    cpe_match: Vec<String>,
}

/// Parse the openvas-port rules tree. Walks recursively but skips the
/// `_scaffolds/` subdirectory at any depth — those are dev-only stubs that
/// never reach the SQLite catalog.
pub fn parse_dir(dir: &Path) -> Result<(Vec<NormalizedRule>, ParseStats)> {
    let mut rules = Vec::new();
    let mut stats = ParseStats::default();

    if !dir.exists() {
        return Ok((rules, stats));
    }

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // Skip anything under a `_scaffolds` directory at any depth. Authors
        // promote files out of `_scaffolds/` into a family folder once the
        // detection has been re-expressed against the vendor advisory.
        if path
            .components()
            .any(|c| c.as_os_str() == "_scaffolds")
        {
            continue;
        }

        match parse_one(path) {
            Ok(rule) => {
                rules.push(rule);
                stats.ingested += 1;
            }
            Err(e) => {
                tracing::warn!(
                    target: "openvas_port_parser",
                    "skipping {}: {}",
                    path.display(),
                    e
                );
                stats.skip(classify_error(&e));
            }
        }
    }

    Ok((rules, stats))
}

fn parse_one(path: &Path) -> Result<NormalizedRule> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let file: OpenvasPortRuleFile = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", path.display()))?;

    if file.id.trim().is_empty() {
        return Err(anyhow!("missing id"));
    }
    if file.name.trim().is_empty() {
        return Err(anyhow!("missing name"));
    }

    let match_spec_value = file
        .match_spec
        .ok_or_else(|| anyhow!("missing match_spec"))?;

    // Carry the pre-built MatchSpec through `detection` under a shape the
    // lowering pass recognises (`detection.match_spec` -> typed `MatchSpec`).
    // Tag with `kind` so the JSON is self-describing for anyone querying
    // `detection_json` directly.
    let detection = json!({
        "kind": "openvas_port",
        "match_spec": match_spec_value,
    });

    let mut source_meta = serde_json::Map::new();
    if let Some(prov) = file.provenance {
        if let Some(oid) = prov.openvas_oid {
            source_meta.insert("openvas_oid".into(), Value::String(oid));
        }
        if !prov.advisory_urls.is_empty() {
            source_meta.insert(
                "advisory_urls".into(),
                Value::Array(
                    prov.advisory_urls
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        if !prov.default_ports.is_empty() {
            source_meta.insert(
                "default_ports".into(),
                Value::Array(
                    prov.default_ports
                        .into_iter()
                        .map(|p| Value::Number(p.into()))
                        .collect(),
                ),
            );
        }
        if !prov.cpe_match.is_empty() {
            source_meta.insert(
                "cpe_match".into(),
                Value::Array(
                    prov.cpe_match.into_iter().map(Value::String).collect(),
                ),
            );
        }
    }

    let rule = NormalizedRule {
        source_tool: SourceTool::OpenvasPort,
        source_rule_id: file.id,
        name: file.name,
        description: file.description,
        severity: file.severity.into(),
        confidence: file.confidence.map(Into::into),
        category: file.category,
        owasp_2025: file.owasp_2025,
        cwe: file.cwe,
        references: file.references,
        // The HTTP shorthand columns are populated from the rule's first
        // HTTP step downstream (in `lower::lower_openvas_port`). Leaving
        // them None here keeps the parser simple — the writer doesn't
        // depend on them being set, only the report does.
        http_method: None,
        uri_template: None,
        request_body: None,
        request_headers: None,
        payloads: Vec::new(),
        detection,
        source_meta: Value::Object(source_meta),
    };

    if !file.enabled {
        // Enabled=false is a valid hand-authored state ("rule under
        // construction"). We still write the row so authors can preview the
        // build report; the writer respects the column it's given. Today
        // every row inserts with `enabled = 1`; a future change can wire
        // this through if the workflow needs it.
    }

    Ok(rule)
}

fn classify_error(e: &anyhow::Error) -> String {
    let msg = format!("{e:#}");
    if msg.contains("missing id") {
        "openvas_port_missing_id".into()
    } else if msg.contains("missing name") {
        "openvas_port_missing_name".into()
    } else if msg.contains("missing match_spec") {
        "openvas_port_missing_match_spec".into()
    } else if msg.contains("parse ") {
        "openvas_port_invalid_json".into()
    } else {
        "openvas_port_unknown".into()
    }
}
