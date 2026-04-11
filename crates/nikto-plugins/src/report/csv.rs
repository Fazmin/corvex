//! CSV report.

use nikto_core::error::Result;
use nikto_core::report::{ReportFormat, ReportItem, ReportSink};
use nikto_core::state::GlobalState;
use nikto_core::target::Mark;
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
                "hostname,ip,port,ssl,nikto_id,method,uri,message,references"
            )?;
            self.header_written = true;
        }
        Ok(())
    }

    fn item(&mut self, mark: &Mark, item: &ReportItem) -> Result<()> {
        writeln!(
            self.out,
            "{},{},{},{},{},{},{},{},{}",
            escape(&mark.hostname),
            escape(&mark.ip.map(|i| i.to_string()).unwrap_or_default()),
            mark.port,
            mark.ssl,
            escape(&item.nikto_id),
            escape(&item.method),
            escape(&item.uri),
            escape(&item.message),
            escape(&item.refs),
        )?;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}
