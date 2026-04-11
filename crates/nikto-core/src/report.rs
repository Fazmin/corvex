//! Findings + report sink trait.

use crate::error::Result;
use crate::state::GlobalState;
use crate::target::Mark;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportItem {
    pub nikto_id: String,
    pub method: String,
    pub uri: String,
    pub message: String,
    pub refs: String,
    pub data: String,
    pub plugin: String,
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
