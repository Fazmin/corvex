//! OWASP ZAP rule descriptor parser.
//!
//! ZAP active and passive scan rules are implemented in Java; the executable
//! logic doesn't port directly. The vendoring step (see rules-sources/zap/
//! VENDOR.md) extracts portable *metadata* — id, name, description, risk,
//! confidence, CWE, references, payload arrays, and pattern strings — into
//! one JSON file per rule. This parser consumes that JSON.
//!
//! In Phase 1 we just persist the metadata. Phase 2 will design the runtime
//! matcher and decide how (or whether) to execute each rule.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use walkdir::WalkDir;

use crate::normalized::{NormalizedRule, ParseStats, SourceTool};
use crate::severity;

#[derive(Debug, Deserialize)]
struct ZapRuleDescriptor {
    id: serde_json::Value,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    solution: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    riskcode: Option<i64>,
    #[serde(default)]
    confidence: Option<i64>,
    #[serde(default)]
    cwe_id: Option<i64>,
    #[serde(default)]
    wasc_id: Option<i64>,
    #[serde(default)]
    alert_tags: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    payloads: Vec<String>,
    #[serde(default)]
    patterns: Vec<String>,
    #[serde(default)]
    raw_class: Option<String>,
    #[serde(default)]
    passive: bool,
}

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
        match parse_one(path) {
            Ok(rule) => {
                rules.push(rule);
                stats.ingested += 1;
            }
            Err(e) => {
                tracing::warn!(
                    target: "zap_parser",
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
    let desc: ZapRuleDescriptor = serde_json::from_str(&raw)
        .with_context(|| format!("parse JSON at {}", path.display()))?;

    let id = match &desc.id {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        other => anyhow::bail!("rule id must be a string or number, got {other:?}"),
    };

    if id.trim().is_empty() {
        anyhow::bail!("missing rule id");
    }
    if desc.name.trim().is_empty() {
        anyhow::bail!("missing rule name");
    }

    let sev = severity::severity_from_zap_riskcode(desc.riskcode.unwrap_or(0));
    let conf = desc
        .confidence
        .and_then(severity::confidence_from_zap_code);

    let references: Vec<String> = desc
        .reference
        .as_deref()
        .unwrap_or("")
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let owasp = owasp_from_alert_tags(desc.alert_tags.as_ref());
    let category = category_from_class_or_name(desc.raw_class.as_deref(), &desc.name);

    let detection = json!({
        "kind": "zap_metadata",
        "payloads": desc.payloads,
        "patterns": desc.patterns,
        "raw_class": desc.raw_class,
        "passive": desc.passive,
    });

    let source_meta = json!({
        "wasc_id": desc.wasc_id,
        "alert_tags": desc.alert_tags,
        "solution": desc.solution,
        "passive": desc.passive,
    });

    Ok(NormalizedRule {
        source_tool: SourceTool::Zap,
        source_rule_id: id,
        name: desc.name,
        description: desc.description,
        severity: sev,
        confidence: conf,
        category,
        owasp_2025: owasp,
        cwe: desc.cwe_id,
        references,
        http_method: None,
        uri_template: None,
        request_body: None,
        request_headers: None,
        payloads: desc.payloads,
        detection,
        source_meta,
    })
}

/// Map a ZAP `alert_tags` map (keys like `OWASP_2021_A03`) to an OWASP-2025
/// bucket. The OWASP Top 10 categories are largely stable across the 2021
/// and 2025 revisions, so we treat them as equivalent for now.
fn owasp_from_alert_tags(
    tags: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Option<String> {
    let tags = tags?;
    for key in tags.keys() {
        if let Some(rest) = key.strip_prefix("OWASP_2021_") {
            if rest.starts_with('A') && rest.len() >= 3 {
                return Some(rest[..3].to_string());
            }
        }
        if let Some(rest) = key.strip_prefix("OWASP_2025_") {
            if rest.starts_with('A') && rest.len() >= 3 {
                return Some(rest[..3].to_string());
            }
        }
    }
    None
}

/// Best-effort coarse category from the Java class name or rule name.
fn category_from_class_or_name(class: Option<&str>, name: &str) -> Option<String> {
    let hay = format!(
        "{} {}",
        class.unwrap_or("").to_ascii_lowercase(),
        name.to_ascii_lowercase()
    );
    let cat = if hay.contains("sql") {
        "sqli"
    } else if hay.contains("xss") || hay.contains("crosssite") || hay.contains("cross site") {
        "xss"
    } else if hay.contains("ssrf") {
        "ssrf"
    } else if hay.contains("xxe") {
        "xxe"
    } else if hay.contains("ssti") {
        "ssti"
    } else if hay.contains("rfi") || hay.contains("remote file") {
        "rfi"
    } else if hay.contains("lfi") || hay.contains("path traversal") {
        "lfi"
    } else if hay.contains("redirect") {
        "open-redirect"
    } else if hay.contains("crlf") {
        "crlf"
    } else if hay.contains("command") && hay.contains("inject") {
        "cmdi"
    } else if hay.contains("csp") || hay.contains("content security") {
        "header-csp"
    } else if hay.contains("hsts") || hay.contains("strict-transport") {
        "header-hsts"
    } else if hay.contains("cors") {
        "header-cors"
    } else if hay.contains("cookie") {
        "cookie"
    } else if hay.contains("auth") {
        "auth"
    } else if hay.contains("info") && hay.contains("disclos") {
        "info-disclosure"
    } else {
        return None;
    };
    Some(cat.to_string())
}

fn classify_error(e: &anyhow::Error) -> String {
    let msg = format!("{e:#}");
    if msg.contains("parse JSON") {
        "json_parse_error".into()
    } else if msg.contains("missing rule id") {
        "missing_id".into()
    } else if msg.contains("missing rule name") {
        "missing_name".into()
    } else if msg.contains("read ") {
        "io_error".into()
    } else {
        "other_error".into()
    }
}
