//! CSV report.

use corvex_core::error::Result;
use corvex_core::report::{ReportFormat, ReportItem, ReportSink};
use corvex_core::state::GlobalState;
use corvex_core::target::Mark;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct CsvSink {
    out: Box<dyn Write + Send>,
    _path: Option<PathBuf>,
    header_written: bool,
}

impl CsvSink {
    pub fn new(path: Option<&Path>) -> Self {
        Self {
            out: super::open_writer(path),
            _path: path.map(|p| p.to_path_buf()),
            header_written: false,
        }
    }
}

fn escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

impl ReportSink for CsvSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Csv
    }

    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        if !self.header_written {
            writeln!(
                self.out,
                "hostname,ip,port,ssl,severity,corvex_id,method,uri,message,references,cve,cvss"
            )?;
            self.header_written = true;
        }
        Ok(())
    }

    fn item(&mut self, mark: &Mark, item: &ReportItem) -> Result<()> {
        writeln!(
            self.out,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            escape(&mark.hostname),
            escape(&mark.ip.map(|i| i.to_string()).unwrap_or_default()),
            mark.port,
            mark.ssl,
            escape(&item.severity.to_string()),
            escape(&item.corvex_id),
            escape(&item.method),
            escape(&item.uri),
            escape(&item.message),
            escape(&item.refs),
            escape(item.cve.as_deref().unwrap_or("")),
            item.cvss.map(|v| format!("{v:.1}")).unwrap_or_default(),
        )?;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}
