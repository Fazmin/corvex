//! corvex-rules — runtime read-only access to the unified `rules.sqlite`,
//! plus the `MatchSpec` AST and multi-step engine that consume it.
//!
//! Owns the heavy serde-derived recursive `Cond` enum so corvex-core's
//! compile time stays low. Other crates pull in this one when they need
//! the matcher; corvex-core only knows the [`RuleProvider`] trait.

// `matcher::spec::Cond` is a recursive tagged-enum that serde monomorphises
// deeply when computing trait bounds; the default 128-level limit overflows
// during `serde_json::Serializer<&mut Vec<u8>>` resolution.
#![recursion_limit = "4096"]

pub mod matcher;

use std::path::Path;
use std::sync::Mutex;

use crate::matcher::MatchSpec;
use corvex_core::matcher::{ExecutableRule, RuleProvider};
use rusqlite::{Connection, OpenFlags};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum RuleStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("invalid match_spec_json for rule_id={rule_id} ({source_tool}/{source_rule_id}): {error}")]
    BadMatchSpec {
        rule_id: i64,
        source_tool: String,
        source_rule_id: String,
        error: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceTool {
    Nikto,
    Zap,
    Burp,
}

impl SourceTool {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceTool::Nikto => "nikto",
            SourceTool::Zap => "zap",
            SourceTool::Burp => "burp",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "nikto" => Some(SourceTool::Nikto),
            "zap" => Some(SourceTool::Zap),
            "burp" => Some(SourceTool::Burp),
            _ => None,
        }
    }
}

/// One row of `rules.sqlite` plus its parsed `MatchSpec`.
#[derive(Debug, Clone)]
pub struct Rule {
    pub rule_id: i64,
    pub source_tool: SourceTool,
    pub source_rule_id: String,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub category: Option<String>,
    pub owasp_2025: Option<String>,
    pub cwe: Option<i64>,
    pub references: Vec<String>,
    pub match_spec: MatchSpec,
}

/// Read-only handle to the unified rules catalog.
///
/// One process opens the SQLite file once and shares a single
/// [`Mutex<Connection>`] (mirrors the pattern used by
/// [`corvex_core::vulndb`] and `corvex-desktop::exploitdb`). Reads are
/// serialised through the mutex; this is fine because rule loading happens
/// once at scan start and the per-rule iterator caches results in a Vec
/// before the scan begins.
pub struct RuleStore {
    conn: Mutex<Connection>,
}

impl RuleStore {
    /// Open the catalog at `path` for reading. Fails if the file isn't a
    /// valid SQLite produced by `corvex-rules-builder` (no `rules` table).
    pub fn open(path: &Path) -> Result<Self, RuleStoreError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        // Smoke-check: rules table must exist.
        conn.prepare("SELECT 1 FROM rules LIMIT 1")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Total enabled-rule count across all sources.
    pub fn count(&self) -> Result<u64, RuleStoreError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM rules WHERE enabled = 1",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Per-source counts. Useful for the scan logger / UI.
    pub fn count_by_source(&self) -> Result<Vec<(String, u64)>, RuleStoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT source_tool, COUNT(*)
               FROM rules
              WHERE enabled = 1
           GROUP BY source_tool
           ORDER BY source_tool",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Snapshot every rule whose `match_spec_json` parses as a valid
    /// [`MatchSpec`]. Rows that fail to parse are logged at warn and
    /// dropped. The scan-start cost of this is bounded by the rule count
    /// (single linear pass), so callers should call this once and reuse
    /// the resulting Vec for the duration of the scan.
    pub fn load_executable(
        &self,
        sources: &[SourceTool],
    ) -> Result<Vec<Rule>, RuleStoreError> {
        let conn = self.conn.lock().unwrap();
        let where_src = if sources.is_empty() {
            String::new()
        } else {
            let placeholders: Vec<&'static str> = sources.iter().map(|_| "?").collect();
            format!(" AND source_tool IN ({})", placeholders.join(","))
        };
        let sql = format!(
            "SELECT rule_id, source_tool, source_rule_id, name, description,
                    severity, category, owasp_2025, cwe, refs_json,
                    match_spec_json
               FROM rules
              WHERE enabled = 1 AND match_spec_json IS NOT NULL{}
           ORDER BY rule_id",
            where_src
        );
        let mut stmt = conn.prepare(&sql)?;
        let source_strs: Vec<&'static str> = sources.iter().map(|s| s.as_str()).collect();
        let params: Vec<&dyn rusqlite::ToSql> = source_strs
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();
        let raw_rows = stmt.query_map(params.as_slice(), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<i64>>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, String>(10)?,
            ))
        })?;

        let mut out: Vec<Rule> = Vec::new();
        for row in raw_rows {
            let (
                rule_id,
                source_tool_raw,
                source_rule_id,
                name,
                description,
                severity,
                category,
                owasp_2025,
                cwe,
                refs_json,
                match_spec_json,
            ) = row?;

            let source_tool = match SourceTool::parse(&source_tool_raw) {
                Some(s) => s,
                None => {
                    tracing::warn!(
                        target: "rule_store",
                        "skipping rule {rule_id}: unknown source_tool `{source_tool_raw}`"
                    );
                    continue;
                }
            };

            let references: Vec<String> =
                serde_json::from_str(&refs_json).unwrap_or_default();

            let match_spec: MatchSpec = match serde_json::from_str(&match_spec_json) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        target: "rule_store",
                        "skipping rule {rule_id} ({source_tool_raw}/{source_rule_id}): bad match_spec_json: {e}"
                    );
                    continue;
                }
            };

            out.push(Rule {
                rule_id,
                source_tool,
                source_rule_id,
                name,
                description,
                severity,
                category,
                owasp_2025,
                cwe,
                references,
                match_spec,
            });
        }

        Ok(out)
    }
}

impl RuleProvider for RuleStore {
    fn iter_executable(&self, sources: &[&str]) -> Vec<ExecutableRule> {
        let parsed: Vec<SourceTool> = sources
            .iter()
            .filter_map(|s| SourceTool::parse(s))
            .collect();
        match self.load_executable(&parsed) {
            Ok(rules) => rules
                .into_iter()
                .map(|r| ExecutableRule {
                    rule_id: r.rule_id,
                    source_tool: r.source_tool.as_str().to_string(),
                    source_rule_id: r.source_rule_id,
                    name: r.name,
                    description: r.description,
                    severity: r.severity,
                    category: r.category,
                    owasp_2025: r.owasp_2025,
                    cwe: r.cwe,
                    references: r.references,
                    // Re-serialise back to JSON for the trait boundary;
                    // RulesPlugin calls `corvex_rules::matcher::parse_json`
                    // to recover the strongly-typed AST. The double trip
                    // is one allocation per rule and cheap relative to the
                    // ~7.5k-rule scan loop body.
                    match_spec: serde_json::to_value(&r.match_spec)
                        .unwrap_or(serde_json::Value::Null),
                })
                .collect(),
            Err(e) => {
                tracing::error!(target: "rule_store", "iter_executable failed: {e}");
                Vec::new()
            }
        }
    }

    fn count_by_source(&self) -> Vec<(String, u64)> {
        match RuleStore::count_by_source(self) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(target: "rule_store", "count_by_source failed: {e}");
                Vec::new()
            }
        }
    }
}

