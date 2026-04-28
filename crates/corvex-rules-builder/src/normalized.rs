//! Common normalised type that every parser emits and the writer consumes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        match s.trim().to_ascii_lowercase().as_str() {
            "nikto" => Some(SourceTool::Nikto),
            "zap" => Some(SourceTool::Zap),
            "burp" => Some(SourceTool::Burp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
        }
    }
}

/// What every parser emits, one per upstream rule.
///
/// The `detection` field is intentionally a serde_json::Value: each source
/// expresses detection logic in incompatible shapes (Nikto's CODE/BODY DSL,
/// ZAP's payload+pattern arrays, Burp's BCheck `given/if/then` blocks).
/// Phase 1 just stores it. Phase 2 will design the runtime matcher and decide
/// how to interpret these.
#[derive(Debug, Clone)]
pub struct NormalizedRule {
    pub source_tool: SourceTool,
    pub source_rule_id: String,
    pub name: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub confidence: Option<Confidence>,
    pub category: Option<String>,
    pub owasp_2025: Option<String>,
    pub cwe: Option<i64>,
    pub references: Vec<String>,
    pub http_method: Option<String>,
    pub uri_template: Option<String>,
    pub request_body: Option<String>,
    pub request_headers: Option<String>,
    pub payloads: Vec<String>,
    pub detection: serde_json::Value,
    pub source_meta: serde_json::Value,
}

/// Counted reason a parser skipped a candidate rule. Reasons are aggregated
/// in the build report so the user can see why coverage isn't 100%.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    pub ingested: u64,
    pub skipped_by_reason: std::collections::BTreeMap<String, u64>,
}

impl ParseStats {
    pub fn skip(&mut self, reason: impl Into<String>) {
        *self.skipped_by_reason.entry(reason.into()).or_default() += 1;
    }

    pub fn skipped_total(&self) -> u64 {
        self.skipped_by_reason.values().sum()
    }
}
