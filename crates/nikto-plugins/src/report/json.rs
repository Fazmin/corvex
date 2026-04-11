//! JSON report — accumulates findings in memory then writes one document.

use nikto_core::error::Result;
use nikto_core::report::{ReportFormat, ReportItem, ReportSink};
use nikto_core::state::GlobalState;
use nikto_core::target::Mark;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

#[derive(Default, Serialize)]
struct JsonDoc {
    product: String,
    version: String,
    scan: ScanSummary,
    hosts: Vec<HostSection>,
}

#[derive(Default, Serialize)]
struct ScanSummary {
    total_requests: u64,
    total_findings: u64,
    total_errors: u64,
    hosts_completed: u64,
    elapsed_secs: u64,
}

#[derive(Serialize, Default)]
struct HostSection {
    hostname: String,
    ip: Option<String>,
    port: u16,
    ssl: bool,
    banner: Option<String>,
    findings: Vec<ReportItem>,
}

pub struct JsonSink {
    doc: JsonDoc,
    current: Option<HostSection>,
    out: Box<dyn Write + Send>,
    _path: Option<PathBuf>,
}

impl JsonSink {
    pub fn new(path: Option<&Path>) -> Self {
        Self {
            doc: JsonDoc::default(),
            current: None,
            out: super::open_writer(path),
            _path: path.map(|p| p.to_path_buf()),
        }
    }
}

impl ReportSink for JsonSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Json
    }

    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        self.doc.product = nikto_core::PRODUCT_NAME.into();
        self.doc.version = nikto_core::VERSION.into();
        Ok(())
    }

    fn host_start(&mut self, mark: &Mark) -> Result<()> {
        self.current = Some(HostSection {
            hostname: mark.hostname.clone(),
            ip: mark.ip.map(|i| i.to_string()),
            port: mark.port,
            ssl: mark.ssl,
            banner: mark.banner.clone(),
            findings: Vec::new(),
        });
        Ok(())
    }

    fn item(&mut self, _mark: &Mark, item: &ReportItem) -> Result<()> {
        if let Some(h) = self.current.as_mut() {
            h.findings.push(item.clone());
        }
        Ok(())
    }

    fn host_end(&mut self, _mark: &Mark) -> Result<()> {
        if let Some(h) = self.current.take() {
            self.doc.hosts.push(h);
        }
        Ok(())
    }

    fn summary(&mut self, state: &GlobalState) -> Result<()> {
        self.doc.scan = ScanSummary {
            total_requests: state.total_requests.load(Ordering::Relaxed),
            total_findings: state.total_findings.load(Ordering::Relaxed),
            total_errors: state.total_errors.load(Ordering::Relaxed),
            hosts_completed: state.hosts_completed.load(Ordering::Relaxed),
            elapsed_secs: state.elapsed_secs(),
        };
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        let s = serde_json::to_string_pretty(&self.doc)
            .map_err(|e| nikto_core::NiktoError::other(format!("json: {e}")))?;
        self.out.write_all(s.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        Ok(())
    }
}
