//! `TauriEventSink` — a `ReportSink` implementation that pushes findings
//! and lifecycle events into the Tauri event bus instead of writing them
//! to a file. The frontend subscribes per-scan by UUID.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use corvex_core::error::Result as CorvexResult;
use corvex_core::http::tls::SslInfo;
use corvex_core::report::{ReportFormat, ReportItem, ReportSink};
use corvex_core::state::GlobalState;
use corvex_core::target::Mark;
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

use crate::asset_identity::normalize_host;
use crate::history::HistoryDb;

/// Per-host preamble.
#[derive(Debug, Clone, Serialize)]
pub struct HostPayload {
    pub ident: String,
    pub hostname: String,
    pub ip: Option<String>,
    pub port: u16,
    pub ssl: bool,
    pub banner: Option<String>,
}

impl From<&Mark> for HostPayload {
    fn from(m: &Mark) -> Self {
        Self {
            ident: m.ident.clone(),
            hostname: m.hostname.clone(),
            ip: m.ip.map(|i| i.to_string()),
            port: m.port,
            ssl: m.ssl,
            banner: m.banner.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingPayload {
    pub host: String,
    pub port: u16,
    pub corvex_id: String,
    pub method: String,
    pub uri: String,
    pub message: String,
    pub refs: String,
    pub plugin: String,
    pub severity: String,
    pub cve: Option<String>,
    pub cvss: Option<f32>,
    pub epss_score: Option<f32>,
    pub epss_percentile: Option<f32>,
    pub fix_version: Option<String>,
    pub component: Option<String>,
    pub component_version: Option<String>,
    pub details: Option<String>,
}

impl FindingPayload {
    pub fn from_parts(mark: &Mark, item: &ReportItem) -> Self {
        Self {
            host: mark.hostname.clone(),
            port: mark.port,
            corvex_id: item.corvex_id.clone(),
            method: item.method.clone(),
            uri: item.uri.clone(),
            message: item.message.clone(),
            refs: item.refs.clone(),
            plugin: item.plugin.clone(),
            severity: item.severity.to_string(),
            cve: item.cve.clone(),
            cvss: item.cvss,
            epss_score: item.epss_score,
            epss_percentile: item.epss_percentile,
            fix_version: item.fix_version.clone(),
            component: item.component.clone(),
            component_version: item.component_version.clone(),
            details: if item.data.is_empty() { None } else { Some(item.data.clone()) },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SslPayload<'a> {
    pub host: String,
    pub port: u16,
    pub info: &'a SslInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryPayload {
    pub total_requests: u64,
    pub total_findings: u64,
    pub total_errors: u64,
    pub hosts_completed: u64,
    pub elapsed_secs: u64,
}

impl From<&GlobalState> for SummaryPayload {
    fn from(s: &GlobalState) -> Self {
        Self {
            total_requests: s.total_requests.load(Ordering::Relaxed),
            total_findings: s.total_findings.load(Ordering::Relaxed),
            total_errors: s.total_errors.load(Ordering::Relaxed),
            hosts_completed: s.hosts_completed.load(Ordering::Relaxed),
            elapsed_secs: s.elapsed_secs(),
        }
    }
}

/// The streaming sink. Instantiated per scan; dropped when the scan ends.
///
/// Findings are emitted to the Tauri event bus *and* persisted to
/// `scan_findings` (when a HistoryDb handle is provided) so the asset
/// view can render them later, even after the scan window has closed.
pub struct TauriEventSink {
    app: AppHandle,
    scan_id: Uuid,
    history: Option<Arc<HistoryDb>>,
    history_row_id: Option<i64>,
}

impl TauriEventSink {
    pub fn new(app: AppHandle, scan_id: Uuid) -> Self {
        Self {
            app,
            scan_id,
            history: None,
            history_row_id: None,
        }
    }

    /// Attach a history-DB handle + the `scans.id` rowid so per-finding
    /// rows get persisted under the right parent scan.
    pub fn with_history(
        mut self,
        history: Arc<HistoryDb>,
        history_row_id: Option<i64>,
    ) -> Self {
        self.history = Some(history);
        self.history_row_id = history_row_id;
        self
    }

    fn ev(&self, kind: &str) -> String {
        format!("scan://{}/{}", self.scan_id, kind)
    }
}

impl ReportSink for TauriEventSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Json
    }

    fn head(&mut self, _state: &GlobalState) -> CorvexResult<()> {
        let _ = self.app.emit(&self.ev("start"), self.scan_id.to_string());
        Ok(())
    }

    fn host_start(&mut self, mark: &Mark) -> CorvexResult<()> {
        let _ = self
            .app
            .emit(&self.ev("host-start"), HostPayload::from(mark));
        Ok(())
    }

    fn ssl_info(&mut self, mark: &Mark) -> CorvexResult<()> {
        if let Some(info) = mark.ssl_info.as_ref() {
            let payload = SslPayload {
                host: mark.hostname.clone(),
                port: mark.port,
                info,
            };
            let _ = self.app.emit(&self.ev("ssl"), payload);
        }
        Ok(())
    }

    fn item(&mut self, mark: &Mark, item: &ReportItem) -> CorvexResult<()> {
        let _ = self
            .app
            .emit(&self.ev("finding"), FindingPayload::from_parts(mark, item));
        if let Some(history) = self.history.as_ref() {
            let host_norm = normalize_host(&mark.hostname);
            if !host_norm.is_empty() {
                if let Err(e) = history.insert_scan_finding(
                    self.history_row_id,
                    &host_norm,
                    mark.port,
                    Some(item.method.as_str()),
                    item.uri.as_str(),
                    item.plugin.as_str(),
                    Some(item.corvex_id.as_str()),
                    item.severity.to_string().as_str(),
                    item.message.as_str(),
                    Some(item.refs.as_str()),
                    item.cve.as_deref(),
                    item.cvss,
                    item.epss_score,
                    item.epss_percentile,
                    item.fix_version.as_deref(),
                    item.component.as_deref(),
                    item.component_version.as_deref(),
                    if item.data.is_empty() { None } else { Some(item.data.as_str()) },
                ) {
                    tracing::warn!(
                        target: "history",
                        "scan_findings insert failed: {e}"
                    );
                }
            }
        }
        Ok(())
    }

    fn host_end(&mut self, mark: &Mark) -> CorvexResult<()> {
        let _ = self.app.emit(&self.ev("host-end"), HostPayload::from(mark));
        Ok(())
    }

    fn summary(&mut self, state: &GlobalState) -> CorvexResult<()> {
        let _ = self
            .app
            .emit(&self.ev("summary"), SummaryPayload::from(state));
        Ok(())
    }

    fn close(&mut self) -> CorvexResult<()> {
        let _ = self.app.emit(&self.ev("close"), ());
        Ok(())
    }
}
