//! Finding model — a single issue produced by a check against an
//! exchange. The struct is `Serialize` so it ships cleanly through the
//! Tauri IPC boundary.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use corvex_proxy::ExchangeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl From<corvex_intel::headers::Severity> for Severity {
    fn from(s: corvex_intel::headers::Severity) -> Self {
        use corvex_intel::headers::Severity as S;
        match s {
            S::Info => Self::Info,
            S::Low => Self::Low,
            S::Medium => Self::Medium,
            S::High => Self::High,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    /// Check that produced the finding (stable id).
    pub check_id: String,
    /// Exchange that triggered the finding. Active checks also carry
    /// the parent exchange here (the `Check` origin stores its own
    /// parent reference on the child exchange).
    pub exchange_id: ExchangeId,
    pub severity: Severity,
    pub title: String,
    pub description: Option<String>,
    /// Free-form JSON object with matched patterns, extracted values,
    /// and similar evidence used to reconstruct the context.
    pub evidence: serde_json::Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl Finding {
    pub fn new(
        check_id: impl Into<String>,
        exchange_id: ExchangeId,
        severity: Severity,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            check_id: check_id.into(),
            exchange_id,
            severity,
            title: title.into(),
            description: None,
            evidence: serde_json::Value::Null,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn with_description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    pub fn with_evidence(mut self, v: serde_json::Value) -> Self {
        self.evidence = v;
        self
    }
}
