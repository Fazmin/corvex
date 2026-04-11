//! SQL report — emits INSERT statements matching the
//! `documentation/nikto_schema_*.sql` schemas. Output is DB-agnostic and
//! works with both MySQL and PostgreSQL if the table already exists.

use nikto_core::error::Result;
use nikto_core::report::{ReportFormat, ReportItem, ReportSink};
use nikto_core::state::GlobalState;
use nikto_core::target::Mark;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct SqlSink {
    out: Box<dyn Write + Send>,
    _path: Option<PathBuf>,
    scan_id: String,
}

impl SqlSink {
    pub fn new(path: Option<&Path>) -> Self {
        // Short random scan id
        let scan_id = format!(
            "{:08x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
        );
        Self {
            out: super::open_writer(path),
            _path: path.map(|p| p.to_path_buf()),
            scan_id,
        }
    }
}

fn sq(s: &str) -> String {
    s.replace('\'', "''")
}

impl ReportSink for SqlSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Sql
    }

    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        writeln!(self.out, "-- Nikto {} SQL report", nikto_core::VERSION)?;
        writeln!(self.out, "-- scan id: {}", self.scan_id)?;
        Ok(())
    }

    fn item(&mut self, mark: &Mark, item: &ReportItem) -> Result<()> {
        writeln!(
            self.out,
            "INSERT INTO nikto_table (scanid, testid, ip, hostname, port, tls, refs, httpmethod, uri, message) VALUES ('{}','{}','{}','{}',{},{},'{}','{}','{}','{}');",
            self.scan_id,
            sq(&item.nikto_id),
            sq(&mark.ip.map(|i| i.to_string()).unwrap_or_default()),
            sq(&mark.hostname),
            mark.port,
            if mark.ssl { 1 } else { 0 },
            sq(&item.refs),
            sq(&item.method),
            sq(&item.uri),
            sq(&item.message),
        )?;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}
