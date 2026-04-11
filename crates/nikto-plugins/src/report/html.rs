//! Simple HTML report. A richer implementation could load the
//! `program/templates/htm_*.tmpl` placeholder files; for now we inline a
//! minimal layout that renders correctly in any browser.

use nikto_core::error::Result;
use nikto_core::report::{ReportFormat, ReportItem, ReportSink};
use nikto_core::state::GlobalState;
use nikto_core::target::Mark;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct HtmlSink {
    out: Box<dyn Write + Send>,
    _path: Option<PathBuf>,
}

impl HtmlSink {
    pub fn new(path: Option<&Path>) -> Self {
        Self {
            out: super::open_writer(path),
            _path: path.map(|p| p.to_path_buf()),
        }
    }
}

fn he(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl ReportSink for HtmlSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Html
    }

    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        writeln!(
            self.out,
            "<!doctype html><html><head><title>Nikto Scan Report</title>\
             <style>body{{font-family:sans-serif}} .item{{margin:.5em 0;padding:.5em;border-left:3px solid #c33}}</style>\
             </head><body><h1>Nikto {} report</h1>",
            nikto_core::VERSION
        )?;
        Ok(())
    }

    fn host_start(&mut self, mark: &Mark) -> Result<()> {
        writeln!(
            self.out,
            "<h2>{} ({}) port {} {}</h2>",
            he(&mark.hostname),
            he(&mark.ip.map(|i| i.to_string()).unwrap_or_default()),
            mark.port,
            if mark.ssl { "SSL" } else { "" }
        )?;
        if let Some(b) = &mark.banner {
            writeln!(self.out, "<p>Server: {}</p>", he(b))?;
        }
        writeln!(self.out, "<div class=\"findings\">")?;
        Ok(())
    }

    fn item(&mut self, _mark: &Mark, item: &ReportItem) -> Result<()> {
        writeln!(
            self.out,
            "<div class=\"item\"><strong>{}</strong> {} {} — {}</div>",
            he(&item.nikto_id),
            he(&item.method),
            he(&item.uri),
            he(&item.message),
        )?;
        Ok(())
    }

    fn host_end(&mut self, _mark: &Mark) -> Result<()> {
        writeln!(self.out, "</div>")?;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        writeln!(self.out, "</body></html>")?;
        self.out.flush()?;
        Ok(())
    }
}
