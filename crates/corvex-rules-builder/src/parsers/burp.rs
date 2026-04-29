//! Burp Suite BCheck parser.
//!
//! BCheck files (`*.bcheck`) ship a small declarative DSL with a `metadata`
//! header (name, description, severity, confidence, tags, author) followed
//! by `given/if/then` blocks describing the actual probe + match logic.
//!
//! Phase 1 pulls the metadata into normalised columns and preserves the
//! probe body verbatim under `detection.kind = "bcheck"` so Phase 2 can
//! decide how to interpret it. We don't try to evaluate or translate the
//! DSL here.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;
use walkdir::WalkDir;

use crate::normalized::{Confidence, NormalizedRule, ParseStats, Severity, SourceTool};
use crate::severity;

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
        if path.extension().and_then(|e| e.to_str()) != Some("bcheck") {
            continue;
        }
        match parse_one(path) {
            Ok(rule) => {
                rules.push(rule);
                stats.ingested += 1;
            }
            Err(e) => {
                tracing::warn!(
                    target: "burp_parser",
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

    let (metadata_lines, body) = split_metadata(&raw)?;
    let meta = parse_metadata_block(&metadata_lines);

    let name = meta
        .get("name")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing metadata.name"))?;

    let description = meta.get("description").cloned();
    let language = meta.get("language").cloned();
    let author = meta.get("author").cloned();
    let tags_raw = meta.get("tags").cloned();

    // Severity may be on metadata or on the `report issue:` line in the body.
    let sev = meta
        .get("severity")
        .map(|s| severity::severity_from_burp_label(s))
        .or_else(|| extract_field_from_body(&body, "severity")
            .as_deref()
            .map(severity::severity_from_burp_label))
        .unwrap_or(Severity::Info);

    let conf: Option<Confidence> = meta
        .get("confidence")
        .and_then(|s| severity::confidence_from_burp_label(s))
        .or_else(|| {
            extract_field_from_body(&body, "confidence")
                .as_deref()
                .and_then(severity::confidence_from_burp_label)
        });

    let tags: Vec<String> = parse_quoted_list(tags_raw.as_deref().unwrap_or(""));
    let category = category_from_tags(&tags, &name);
    let owasp = owasp_from_tags(&tags, &name);

    // BCheck has no native rule ID. Derive a stable one from filename.
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("could not derive rule id from path"))?;
    let id = format!("bcheck-{stem}");

    let detection = json!({
        "kind": "bcheck",
        "language": language,
        "body": body,
        "tags": tags,
    });

    let source_meta = json!({
        "author": author,
        "metadata_raw": metadata_lines,
    });

    Ok(NormalizedRule {
        source_tool: SourceTool::Burp,
        source_rule_id: id,
        name,
        description,
        severity: sev,
        confidence: conf,
        category,
        owasp_2025: owasp,
        cwe: None,
        references: Vec::new(),
        http_method: None,
        uri_template: None,
        request_body: None,
        request_headers: None,
        payloads: Vec::new(),
        detection,
        source_meta,
    })
}

/// Split a BCheck file into the metadata header and the rest. We accept both
/// `metadata { ... }` brace style and `metadata:` indented style — the
/// official PortSwigger samples use the latter.
fn split_metadata(raw: &str) -> Result<(Vec<String>, String)> {
    let lines: Vec<&str> = raw.lines().collect();
    let mut i = 0;
    // Skip leading blank lines and `#`-style comments. Some upstream BChecks
    // start with `#Verified: Yes` or similar provenance comments before the
    // `metadata:` block.
    while i < lines.len() {
        let t = lines[i].trim();
        if t.is_empty() || t.starts_with('#') {
            i += 1;
        } else {
            break;
        }
    }
    if i >= lines.len() {
        anyhow::bail!("empty file");
    }

    let header = lines[i].trim();

    if let Some(rest) = header.strip_prefix("metadata") {
        let rest = rest.trim();
        if rest.starts_with('{') {
            // brace style: collect until matching `}`
            return split_brace_metadata(&lines, i);
        }
        if rest == ":" || rest.is_empty() {
            // indented style: collect contiguous indented lines after the
            // `metadata:` header.
            return split_indent_metadata(&lines, i);
        }
    }

    anyhow::bail!("missing metadata block");
}

fn split_brace_metadata(lines: &[&str], start: usize) -> Result<(Vec<String>, String)> {
    let mut depth = 0i32;
    let mut meta_lines = Vec::new();
    let mut consumed_to = start;

    for (idx, raw_line) in lines.iter().enumerate().skip(start) {
        let line = *raw_line;
        for c in line.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
        meta_lines.push(strip_metadata_decoration(line));
        consumed_to = idx;
        if depth <= 0 && idx > start {
            break;
        }
    }

    let body = lines[consumed_to + 1..].join("\n");
    Ok((meta_lines, body))
}

fn split_indent_metadata(lines: &[&str], start: usize) -> Result<(Vec<String>, String)> {
    let mut meta_lines = Vec::new();
    let mut consumed_to = start; // header line itself
    for (idx, raw_line) in lines.iter().enumerate().skip(start + 1) {
        let line = *raw_line;
        if line.trim().is_empty() {
            consumed_to = idx;
            continue;
        }
        let leading_ws = line.len() - line.trim_start().len();
        if leading_ws == 0 {
            // First non-indented line ends the metadata block.
            break;
        }
        meta_lines.push(line.trim().to_string());
        consumed_to = idx;
    }
    let body = if consumed_to + 1 < lines.len() {
        lines[consumed_to + 1..].join("\n")
    } else {
        String::new()
    };
    Ok((meta_lines, body))
}

fn strip_metadata_decoration(line: &str) -> String {
    let t = line.trim();
    let t = t.trim_start_matches("metadata");
    let t = t.trim_start_matches('{');
    let t = t.trim_end_matches('}');
    t.trim().to_string()
}

/// Parse `key: value` (and `key = value`) lines from the metadata block into
/// a flat map. Values are preserved verbatim apart from leading / trailing
/// whitespace and trailing commas — callers strip surrounding quotes
/// themselves (a list value like `"redirect", "active"` would lose its
/// per-element quoting if blanket-stripped here).
fn parse_metadata_block(lines: &[String]) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for line in lines {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let (k, v) = match split_kv(t) {
            Some(kv) => kv,
            None => continue,
        };
        out.insert(k, unquote_scalar(&v));
    }
    out
}

fn split_kv(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':').or_else(|| line.split_once('='))?;
    let key = k.trim().to_ascii_lowercase();
    if key.is_empty() {
        return None;
    }
    let value = v.trim().trim_end_matches(',').trim().to_string();
    Some((key, value))
}

/// Strip exactly one pair of surrounding double quotes if the whole value is
/// a single quoted string. Leaves multi-element / list values intact.
fn unquote_scalar(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && t.starts_with('"')
        && t.ends_with('"')
        && !t[1..t.len() - 1].contains('"')
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Extract the value of a `key: value` field that appears anywhere in the
/// body (used for `severity` / `confidence` fields written under
/// `report issue:`).
fn extract_field_from_body(body: &str, field: &str) -> Option<String> {
    let needle = format!("{field}:");
    for line in body.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix(&needle) {
            return Some(rest.trim().trim_matches('"').to_string());
        }
    }
    None
}

fn parse_quoted_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quote = false;
    for c in raw.chars() {
        match c {
            '"' => {
                if in_quote {
                    out.push(std::mem::take(&mut buf));
                }
                in_quote = !in_quote;
            }
            _ => {
                if in_quote {
                    buf.push(c);
                }
            }
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

fn category_from_tags(tags: &[String], name: &str) -> Option<String> {
    let hay = format!(
        "{} {}",
        tags.iter().map(|t| t.to_ascii_lowercase()).collect::<Vec<_>>().join(" "),
        name.to_ascii_lowercase()
    );
    let cat = if hay.contains("sqli") || hay.contains("sql injection") {
        "sqli"
    } else if hay.contains("xss") {
        "xss"
    } else if hay.contains("ssrf") {
        "ssrf"
    } else if hay.contains("redirect") {
        "open-redirect"
    } else if hay.contains("xxe") {
        "xxe"
    } else if hay.contains("rce") || hay.contains("command injection") {
        "cmdi"
    } else if hay.contains("misconfig") || hay.contains("listing") {
        "misconfig"
    } else if hay.contains("info-leak") || hay.contains("info leak") || hay.contains("disclosure")
    {
        "info-disclosure"
    } else if hay.contains("auth") {
        "auth"
    } else {
        return None;
    };
    Some(cat.to_string())
}

fn owasp_from_tags(tags: &[String], name: &str) -> Option<String> {
    let hay = format!(
        "{} {}",
        tags.iter().map(|t| t.to_ascii_lowercase()).collect::<Vec<_>>().join(" "),
        name.to_ascii_lowercase()
    );
    if hay.contains("sql") || hay.contains("xss") || hay.contains("xxe") || hay.contains("inject")
    {
        Some("A03".into())
    } else if hay.contains("auth") || hay.contains("idor") {
        Some("A01".into())
    } else if hay.contains("misconfig") || hay.contains("listing") || hay.contains("redirect") {
        Some("A05".into())
    } else if hay.contains("info-leak") || hay.contains("disclosure") {
        Some("A04".into())
    } else {
        None
    }
}

fn classify_error(e: &anyhow::Error) -> String {
    let msg = format!("{e:#}");
    if msg.contains("missing metadata") {
        "missing_metadata".into()
    } else if msg.contains("missing metadata.name") {
        "missing_name".into()
    } else if msg.contains("empty file") {
        "empty_file".into()
    } else if msg.contains("read ") {
        "io_error".into()
    } else {
        "other_error".into()
    }
}
