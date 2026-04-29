//! Build report — per-source counts, skip reasons, severity / OWASP
//! distribution. Both rendered to stdout after a build and queryable via
//! `corvex-rules-builder --report <db>`.

use std::collections::BTreeMap;

use anyhow::Result;
use rusqlite::Connection;

use crate::normalized::{ParseStats, SourceTool};

#[derive(Debug, Clone, Default)]
pub struct BuildReport {
    pub by_source: BTreeMap<String, ParseStats>,
}

impl BuildReport {
    pub fn record(&mut self, source: SourceTool, stats: ParseStats) {
        self.by_source.insert(source.as_str().to_string(), stats);
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("\n=== Ingestion summary ===\n");
        for (source, stats) in &self.by_source {
            out.push_str(&format!(
                "  {:<6}  ingested = {:>6}  skipped = {:>5}\n",
                source,
                stats.ingested,
                stats.skipped_total()
            ));
            if !stats.skipped_by_reason.is_empty() {
                let mut reasons: Vec<_> = stats.skipped_by_reason.iter().collect();
                reasons.sort_by(|a, b| b.1.cmp(a.1));
                for (reason, count) in reasons.iter().take(5) {
                    out.push_str(&format!("            skip[{reason}] = {count}\n"));
                }
            }
        }
        out
    }
}

/// Render an after-the-fact report straight off a built rules.sqlite —
/// the user-facing `corvex-rules-builder --report <db>` subcommand.
pub fn render_db_report(conn: &Connection) -> Result<String> {
    let mut out = String::new();
    out.push_str("\n=== rules.sqlite report ===\n\n");

    // Per-source totals.
    out.push_str("[counts by source]\n");
    let mut stmt = conn
        .prepare("SELECT source_tool, COUNT(*) FROM rules GROUP BY source_tool ORDER BY source_tool")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;
    let mut total: i64 = 0;
    for row in rows {
        let (source, count) = row?;
        out.push_str(&format!("  {:<6}  {}\n", source, count));
        total += count;
    }
    out.push_str(&format!("  total   {}\n\n", total));

    // Severity distribution per source.
    out.push_str("[severity by source]\n");
    let mut stmt = conn.prepare(
        "SELECT source_tool, severity, COUNT(*)
           FROM rules
       GROUP BY source_tool, severity
       ORDER BY source_tool,
                CASE severity
                  WHEN 'critical' THEN 0
                  WHEN 'high'     THEN 1
                  WHEN 'medium'   THEN 2
                  WHEN 'low'      THEN 3
                  WHEN 'info'     THEN 4
                  ELSE 5 END",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (source, severity, count) = row?;
        out.push_str(&format!("  {:<6}  {:<8}  {}\n", source, severity, count));
    }
    out.push('\n');

    // MatchSpec coverage — what fraction of each source has an executable
    // lowering wired up.
    out.push_str("[MatchSpec executable coverage]\n");
    let mut stmt = conn.prepare(
        "SELECT source_tool,
                SUM(CASE WHEN match_spec_json IS NOT NULL THEN 1 ELSE 0 END) AS lowered,
                COUNT(*) AS total
           FROM rules
       GROUP BY source_tool
       ORDER BY source_tool",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (source, lowered, total) = row?;
        let pct = if total > 0 {
            (lowered as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "  {:<6}  {} / {}  ({:.1}%)\n",
            source, lowered, total, pct
        ));
    }
    out.push('\n');

    // OWASP coverage.
    out.push_str("[OWASP-2025 coverage]\n");
    let mut stmt = conn.prepare(
        "SELECT source_tool,
                SUM(CASE WHEN owasp_2025 IS NOT NULL THEN 1 ELSE 0 END) AS mapped,
                COUNT(*) AS total
           FROM rules
       GROUP BY source_tool
       ORDER BY source_tool",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    for row in rows {
        let (source, mapped, total) = row?;
        let pct = if total > 0 {
            (mapped as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "  {:<6}  {} / {}  ({:.1}%)\n",
            source, mapped, total, pct
        ));
    }
    out.push('\n');

    // JSON validity check (verifies invariant 6 from the plan).
    let bad_json: i64 = conn.query_row(
        "SELECT COUNT(*) FROM rules
          WHERE json_valid(refs_json) = 0
             OR json_valid(payloads_json) = 0
             OR json_valid(detection_json) = 0
             OR json_valid(source_meta_json) = 0",
        [],
        |r| r.get(0),
    )?;
    out.push_str(&format!(
        "[invalid JSON columns] {}  (expected 0)\n\n",
        bad_json
    ));

    // Build metadata.
    out.push_str("[build metadata]\n");
    let mut stmt = conn.prepare("SELECT key, value FROM rules_meta ORDER BY key")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (k, v) = row?;
        let snippet = if v.len() > 200 { &v[..200] } else { &v };
        out.push_str(&format!("  {:<28}  {}\n", k, snippet));
    }

    Ok(out)
}
