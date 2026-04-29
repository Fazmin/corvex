//! Bulk insert of normalised rules into rules.sqlite.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::lower;
use crate::normalized::{NormalizedRule, SourceTool};

/// Per-source counters for the lowering pass.
#[derive(Debug, Clone, Default)]
pub struct LoweringStats {
    pub lowered: BTreeMap<String, u64>,
    pub un_lowered_reasons: BTreeMap<String, BTreeMap<String, u64>>,
}

impl LoweringStats {
    fn note_lowered(&mut self, src: SourceTool) {
        *self.lowered.entry(src.as_str().to_string()).or_default() += 1;
    }
    fn note_skip(&mut self, src: SourceTool, reason: impl Into<String>) {
        *self
            .un_lowered_reasons
            .entry(src.as_str().to_string())
            .or_default()
            .entry(reason.into())
            .or_default() += 1;
    }
}

/// Insert every rule in `rules` inside a single transaction. Existing rows
/// with the same `(source_tool, source_rule_id)` are replaced.
///
/// Returns `(rows_written, lowering_stats)`. `match_spec_json` is populated
/// for rules whose `try_lower` returns `Ok(Some(_))` and left `NULL` for
/// rules whose detection logic isn't yet portable.
pub fn insert_rules(
    conn: &mut Connection,
    rules: &[NormalizedRule],
) -> Result<(u64, LoweringStats)> {
    let mut stats = LoweringStats::default();
    let tx = conn.transaction().context("begin transaction")?;
    let mut written = 0u64;
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO rules (
                    source_tool, source_rule_id, name, description,
                    severity, confidence, category, owasp_2025, cwe,
                    refs_json, http_method, uri_template, request_body,
                    request_headers, payloads_json, detection_json,
                    source_meta_json, match_spec_json, enabled
                ) VALUES (
                    ?1, ?2, ?3, ?4,
                    ?5, ?6, ?7, ?8, ?9,
                    ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16,
                    ?17, ?18, 1
                )
                ON CONFLICT(source_tool, source_rule_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    severity = excluded.severity,
                    confidence = excluded.confidence,
                    category = excluded.category,
                    owasp_2025 = excluded.owasp_2025,
                    cwe = excluded.cwe,
                    refs_json = excluded.refs_json,
                    http_method = excluded.http_method,
                    uri_template = excluded.uri_template,
                    request_body = excluded.request_body,
                    request_headers = excluded.request_headers,
                    payloads_json = excluded.payloads_json,
                    detection_json = excluded.detection_json,
                    source_meta_json = excluded.source_meta_json,
                    match_spec_json = excluded.match_spec_json
                ",
            )
            .context("prepare insert")?;

        for rule in rules {
            let refs_json = serde_json::to_string(&rule.references).unwrap_or_else(|_| "[]".into());
            let payloads_json =
                serde_json::to_string(&rule.payloads).unwrap_or_else(|_| "[]".into());
            let detection_json =
                serde_json::to_string(&rule.detection).unwrap_or_else(|_| "{}".into());
            let source_meta_json =
                serde_json::to_string(&rule.source_meta).unwrap_or_else(|_| "{}".into());

            // Lowering pass: produce MatchSpec when possible.
            let match_spec_json: Option<String> = match lower::try_lower(rule) {
                Ok(Some(spec)) => match serde_json::to_string(&spec) {
                    Ok(s) => {
                        stats.note_lowered(rule.source_tool);
                        Some(s)
                    }
                    Err(e) => {
                        stats.note_skip(rule.source_tool, format!("serialize_error: {e}"));
                        None
                    }
                },
                Ok(None) => {
                    let reason = match rule.source_tool {
                        SourceTool::Nikto => "nikto_unlowerable",
                        SourceTool::Zap => "zap_phase_2b",
                        SourceTool::Burp => "burp_phase_2c",
                    };
                    stats.note_skip(rule.source_tool, reason);
                    None
                }
                Err(e) => {
                    stats.note_skip(rule.source_tool, format!("lower_error: {e}"));
                    None
                }
            };

            stmt.execute(rusqlite::params![
                rule.source_tool.as_str(),
                rule.source_rule_id,
                rule.name,
                rule.description,
                rule.severity.as_str(),
                rule.confidence.map(|c| c.as_str()),
                rule.category,
                rule.owasp_2025,
                rule.cwe,
                refs_json,
                rule.http_method,
                rule.uri_template,
                rule.request_body,
                rule.request_headers,
                payloads_json,
                detection_json,
                source_meta_json,
                match_spec_json,
            ])
            .with_context(|| {
                format!(
                    "insert {}/{}",
                    rule.source_tool.as_str(),
                    rule.source_rule_id
                )
            })?;
            written += 1;
        }
    }
    tx.commit().context("commit transaction")?;
    Ok((written, stats))
}

/// Write a single key/value pair into `rules_meta`.
pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO rules_meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .with_context(|| format!("set rules_meta[{key}]"))?;
    Ok(())
}
