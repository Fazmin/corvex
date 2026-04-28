//! Nikto `db_tests` CSV parser.
//!
//! The format and column layout are identical to what
//! `crates/corvex-core/build.rs::load_tests` already consumes — see lines
//! 190-216 there. We re-implement the CSV reader here (rather than depending
//! on `corvex-core`) because the builder is independent of the runtime crate
//! and we don't want to pull the bincode pipeline into this binary.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use crate::normalized::{NormalizedRule, ParseStats, SourceTool};
use crate::severity;

/// Parse a Nikto `db_tests` file into normalised rules.
///
/// Returns the rules plus parse stats. Any malformed row is skipped and
/// counted by reason so the report can show ingestion fidelity.
pub fn parse(path: &Path) -> Result<(Vec<NormalizedRule>, ParseStats)> {
    let raw = read_filtered(path)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .quote(b'"')
        .escape(Some(b'\\'))
        .trim(csv::Trim::None)
        .from_reader(raw.as_bytes());

    let mut rules = Vec::new();
    let mut stats = ParseStats::default();

    for (i, rec) in rdr.records().enumerate() {
        let rec = match rec {
            Ok(r) => r,
            Err(_) => {
                stats.skip("csv_parse_error");
                continue;
            }
        };

        // Skip optional CSV header row.
        if i == 0
            && rec
                .get(0)
                .map(|s| s.eq_ignore_ascii_case("id") || s.eq_ignore_ascii_case("nikto_id"))
                .unwrap_or(false)
        {
            continue;
        }

        if rec.is_empty() {
            stats.skip("empty_row");
            continue;
        }

        let id = rec.get(0).unwrap_or_default().trim().to_string();
        if id.is_empty() {
            stats.skip("missing_id");
            continue;
        }

        let references = rec.get(1).unwrap_or_default().to_string();
        let tuning = rec.get(2).unwrap_or_default().to_string();
        let uri = rec.get(3).unwrap_or_default().to_string();
        let method = rec.get(4).unwrap_or_default().to_string();
        let dsl = rec.get(5).unwrap_or_default().to_string();
        let message = rec.get(6).unwrap_or_default().to_string();
        let data = rec.get(7).unwrap_or_default().to_string();
        let headers = rec.get(8).unwrap_or_default().to_string();

        let sev = severity::severity_from_nikto_tuning(&tuning);

        let refs_vec: Vec<String> = references
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let category = nikto_category_from_tuning(&tuning);

        let rule = NormalizedRule {
            source_tool: SourceTool::Nikto,
            source_rule_id: id,
            name: short_name(&message),
            description: if message.is_empty() { None } else { Some(message.clone()) },
            severity: sev,
            confidence: None,
            category,
            owasp_2025: nikto_owasp_from_tuning(&tuning),
            cwe: None,
            references: refs_vec,
            http_method: if method.is_empty() {
                Some("GET".to_string())
            } else {
                Some(method.clone())
            },
            uri_template: if uri.is_empty() { None } else { Some(uri.clone()) },
            request_body: if data.is_empty() { None } else { Some(data.clone()) },
            request_headers: if headers.is_empty() {
                None
            } else {
                Some(headers.clone())
            },
            payloads: Vec::new(),
            detection: json!({
                "kind": "nikto_dsl",
                "raw": dsl,
                "tuning": tuning,
            }),
            source_meta: json!({
                "raw_message": message,
            }),
        };

        rules.push(rule);
        stats.ingested += 1;
    }

    Ok((rules, stats))
}

/// Read the file, stripping `#` comment lines and blank lines (the same
/// pre-filter applied in corvex-core's build.rs).
fn read_filtered(path: &Path) -> Result<String> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut out = String::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Truncate the Nikto message to a short, human-readable name. Falls back to
/// "Nikto rule" for empty messages.
fn short_name(msg: &str) -> String {
    let trimmed = msg.trim();
    if trimmed.is_empty() {
        return "Nikto rule".to_string();
    }
    let first_line = trimmed.lines().next().unwrap_or(trimmed);
    if first_line.len() <= 120 {
        first_line.to_string()
    } else {
        // Slice on a char boundary so non-ASCII messages don't panic.
        let mut end = 117usize.min(first_line.len());
        while !first_line.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}…", &first_line[..end])
    }
}

/// Map the highest-priority Nikto tuning category to a coarse vuln class.
fn nikto_category_from_tuning(tuning: &str) -> Option<String> {
    let mut best: Option<&'static str> = None;
    let mut best_rank = -1i32;
    for c in tuning.chars() {
        let (cat, rank) = match c {
            '8' => ("rce", 9),
            '9' => ("sqli", 8),
            '4' => ("xss", 7),
            'f' => ("xml-injection", 7),
            '5' | 'c' => ("rfi", 6),
            'a' => ("auth-bypass", 6),
            '0' => ("file-upload", 5),
            '6' => ("dos", 5),
            '7' => ("rfr", 4),
            '2' => ("misconfig", 3),
            'e' => ("admin-console", 3),
            '3' => ("info-disclosure", 2),
            '1' => ("interesting-files", 1),
            'd' => ("webservice", 1),
            'b' => ("software-id", 0),
            _ => continue,
        };
        if rank > best_rank {
            best = Some(cat);
            best_rank = rank;
        }
    }
    best.map(|s| s.to_string())
}

/// Best-effort OWASP Top 10 (2025) bucket for Nikto categories. The mapping
/// is coarse — just enough to be useful for filtering. A `None` here is
/// honest: many Nikto rules don't fit a single OWASP slot.
fn nikto_owasp_from_tuning(tuning: &str) -> Option<String> {
    for c in tuning.chars() {
        let bucket = match c {
            // A03 — Injection
            '8' | '9' | '4' | 'f' | '5' | 'c' => "A03",
            // A01 — Broken Access Control
            'a' => "A01",
            // A05 — Security Misconfiguration
            '2' | 'e' => "A05",
            // A04 — Insecure Design / sensitive data
            '3' => "A04",
            // A06 — Vulnerable & Outdated Components
            'b' => "A06",
            _ => continue,
        };
        return Some(bucket.to_string());
    }
    None
}
