//! Trait abstraction over the unified rule store.
//!
//! `ScanCtx` holds an `Option<Arc<dyn RuleProvider>>`. The underlying
//! `MatchSpec` AST is owned by the `corvex-rules` crate (so its recursive
//! serde-derived types don't bloat corvex-core's compile time); we hand
//! it back here as an opaque `serde_json::Value` and the consumer
//! (`RulesPlugin`) deserialises it via `corvex_rules::matcher::parse_json`.

/// One rule-row's worth of data the matcher needs at scan time.
#[derive(Debug, Clone)]
pub struct ExecutableRule {
    pub rule_id: i64,
    pub source_tool: String,
    pub source_rule_id: String,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub category: Option<String>,
    pub owasp_2025: Option<String>,
    pub cwe: Option<i64>,
    pub references: Vec<String>,
    /// Opaque `MatchSpec` JSON. Deserialise with
    /// `corvex_rules::matcher::parse_json` at the use site.
    pub match_spec: serde_json::Value,
}

/// Read-only snapshot of executable rules. Implementations are expected to
/// load rules eagerly into memory (the typical store has ~7,500 rules — well
/// within reasonable RAM) and serve the snapshot from there.
pub trait RuleProvider: Send + Sync {
    /// All executable rules across the listed source tools. Pass an empty
    /// slice to mean "all sources". Implementations should filter on the
    /// `enabled = 1 AND match_spec_json IS NOT NULL` invariant.
    fn iter_executable(&self, sources: &[&str]) -> Vec<ExecutableRule>;

    /// Per-source executable counts, for logging.
    fn count_by_source(&self) -> Vec<(String, u64)>;
}
