//! Plain-text report (mirrors Perl `corvex_report_text.plugin`).

use corvex_core::error::Result;
use corvex_core::report::{ReportFormat, ReportItem, ReportSink};
use corvex_core::state::GlobalState;
use corvex_core::target::Mark;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

pub struct TextSink {
    out: Box<dyn Write + Send>,
    _path: Option<PathBuf>,
}

impl TextSink {
    pub fn new(path: Option<&Path>) -> Self {
        Self {
            out: super::open_writer(path),
            _path: path.map(|p| p.to_path_buf()),
        }
    }
}

impl ReportSink for TextSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Text
    }

    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        writeln!(
            self.out,
            "- {} v{}",
            corvex_core::PRODUCT_NAME,
            corvex_core::VERSION
        )?;
        writeln!(self.out, "---------------------------------------------------------------------------")?;
        Ok(())
    }

    fn host_start(&mut self, mark: &Mark) -> Result<()> {
        writeln!(self.out, "+ Target IP:          {}", mark.ip.map(|i| i.to_string()).unwrap_or_default())?;
        writeln!(self.out, "+ Target Hostname:    {}", mark.hostname)?;
        writeln!(self.out, "+ Target Port:        {}", mark.port)?;
        if mark.ssl {
            writeln!(self.out, "+ SSL:                true")?;
        }
        if let Some(b) = &mark.banner {
            writeln!(self.out, "+ Server:             {b}")?;
        }
        Ok(())
    }

    fn item(&mut self, _mark: &Mark, item: &ReportItem) -> Result<()> {
        writeln!(
            self.out,
            "+ {}: {} {} - {}",
            item.corvex_id, item.method, item.uri, item.message
        )?;
        if !item.refs.is_empty() {
            writeln!(self.out, "  See: {}", item.refs)?;
        }
        Ok(())
    }

    fn host_end(&mut self, mark: &Mark) -> Result<()> {
        writeln!(
            self.out,
            "+ {} findings on {}",
            mark.counters.vulns(),
            mark.display_name()
        )?;
        writeln!(self.out, "---------------------------------------------------------------------------")?;
        Ok(())
    }

    fn summary(&mut self, state: &GlobalState) -> Result<()> {
        writeln!(
            self.out,
            "+ {} requests in {}s, {} findings, {} errors across {} hosts",
            state.total_requests.load(Ordering::Relaxed),
            state.elapsed_secs(),
            state.total_findings.load(Ordering::Relaxed),
            state.total_errors.load(Ordering::Relaxed),
            state.hosts_completed.load(Ordering::Relaxed),
        )?;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}
