//! Findings + report sink trait.

use crate::error::Result;
use crate::state::GlobalState;
use crate::target::Mark;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level for a finding, ordered from highest to lowest impact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Info = 0,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Info
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    /// Derive severity from a CVSS 3.x score.
    pub fn from_cvss(score: f32) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::Info
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReportFormat {
    Text,
    Csv,
    Json,
    Html,
    Xml,
    Sql,
}

impl ReportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "txt" | "text" => Some(Self::Text),
            "csv" => Some(Self::Csv),
            "json" => Some(Self::Json),
            "htm" | "html" => Some(Self::Html),
            "xml" => Some(Self::Xml),
            "sql" | "sqld" | "sqlg" => Some(Self::Sql),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Html => "html",
            Self::Xml => "xml",
            Self::Sql => "sql",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportItem {
    pub corvex_id: String,
    pub method: String,
    pub uri: String,
    pub message: String,
    pub refs: String,
    pub data: String,
    pub plugin: String,
    /// Severity level of this finding.
    #[serde(default)]
    pub severity: Severity,
    /// CVE identifier, if applicable (e.g. "CVE-2021-44228").
    #[serde(default)]
    pub cve: Option<String>,
    /// CVSS 3.x score (0.0–10.0), if known.
    #[serde(default)]
    pub cvss: Option<f32>,
}

pub trait ReportSink: Send {
    fn format(&self) -> ReportFormat;
    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        Ok(())
    }
    fn host_start(&mut self, _mark: &Mark) -> Result<()> {
        Ok(())
    }
    fn ssl_info(&mut self, _mark: &Mark) -> Result<()> {
        Ok(())
    }
    fn item(&mut self, mark: &Mark, item: &ReportItem) -> Result<()>;
    fn host_end(&mut self, _mark: &Mark) -> Result<()> {
        Ok(())
    }
    fn summary(&mut self, _state: &GlobalState) -> Result<()> {
        Ok(())
    }
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
