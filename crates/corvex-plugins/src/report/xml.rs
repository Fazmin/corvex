//! XML report.

use corvex_core::error::Result;
use corvex_core::report::{ReportFormat, ReportItem, ReportSink};
use corvex_core::state::GlobalState;
use corvex_core::target::Mark;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct XmlSink {
    out: Box<dyn Write + Send>,
    _path: Option<PathBuf>,
    host_open: bool,
}

impl XmlSink {
    pub fn new(path: Option<&Path>) -> Self {
        Self {
            out: super::open_writer(path),
            _path: path.map(|p| p.to_path_buf()),
            host_open: false,
        }
    }
}

fn xe(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

impl ReportSink for XmlSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Xml
    }

    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        writeln!(self.out, "<?xml version=\"1.0\" ?>")?;
        writeln!(
            self.out,
            "<corvexscan version=\"{}\">",
            corvex_core::VERSION
        )?;
        Ok(())
    }

    fn host_start(&mut self, mark: &Mark) -> Result<()> {
        writeln!(
            self.out,
            "  <scandetails targetip=\"{}\" targethostname=\"{}\" targetport=\"{}\" ssl=\"{}\">",
            xe(&mark.ip.map(|i| i.to_string()).unwrap_or_default()),
            xe(&mark.hostname),
            mark.port,
            mark.ssl,
        )?;
        self.host_open = true;
        Ok(())
    }

    fn item(&mut self, _mark: &Mark, item: &ReportItem) -> Result<()> {
        writeln!(
            self.out,
            "    <item id=\"{}\" method=\"{}\"><description>{}</description><uri>{}</uri><references>{}</references></item>",
            xe(&item.corvex_id),
            xe(&item.method),
            xe(&item.message),
            xe(&item.uri),
            xe(&item.refs),
        )?;
        Ok(())
    }

    fn host_end(&mut self, _mark: &Mark) -> Result<()> {
        if self.host_open {
            writeln!(self.out, "  </scandetails>")?;
            self.host_open = false;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        writeln!(self.out, "</corvexscan>")?;
        self.out.flush()?;
        Ok(())
    }
}
