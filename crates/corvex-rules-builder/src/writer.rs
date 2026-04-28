//! Bulk insert of normalised rules into rules.sqlite.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::normalized::NormalizedRule;

/// Insert every rule in `rules` inside a single transaction. Existing rows
/// with the same `(source_tool, source_rule_id)` are replaced.
///
/// Returns the count of rows actually written.
pub fn insert_rules(conn: &mut Connection, rules: &[NormalizedRule]) -> Result<u64> {
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
                    source_meta_json, enabled
                ) VALUES (
                    ?1, ?2, ?3, ?4,
                    ?5, ?6, ?7, ?8, ?9,
                    ?10, ?11, ?12, ?13,
                    ?14, ?15, ?16,
                    ?17, 1
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
                    source_meta_json = excluded.source_meta_json
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
    Ok(written)
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
