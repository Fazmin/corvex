//! HTML report — loads the placeholder-based templates from
//! [../../../../program/templates](../../../../program/templates) at compile
//! time and substitutes `#TEMPL_*#` markers per host / per finding.
//!
//! The upstream Perl `corvex_report_html.plugin` also handles conditional
//! `#TEMPL_*_ROW#` markers: when the preceding `<tr>...<tr>` block should
//! not appear (no SSL info, no references, …), the plugin removes the
//! whole block. We reproduce the same logic with a simple line filter.

use corvex_core::error::Result;
use corvex_core::report::{ReportFormat, ReportItem, ReportSink};
use corvex_core::state::GlobalState;
use corvex_core::target::Mark;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

const TMPL_START: &str = include_str!("../../../../program/templates/htm_start.tmpl");
const TMPL_HEAD: &str = include_str!("../../../../program/templates/htm_host_head.tmpl");
const TMPL_ITEM: &str = include_str!("../../../../program/templates/htm_host_item.tmpl");
const TMPL_END: &str = include_str!("../../../../program/templates/htm_end.tmpl");
const TMPL_SUMMARY: &str = include_str!("../../../../program/templates/htm_summary.tmpl");
const TMPL_CLOSE: &str = include_str!("../../../../program/templates/htm_close.tmpl");

pub struct HtmlSink {
    out: Box<dyn Write + Send>,
    _path: Option<PathBuf>,
    host_counter: u32,
    host_start: SystemTime,
}

impl HtmlSink {
    pub fn new(path: Option<&Path>) -> Self {
        Self {
            out: super::open_writer(path),
            _path: path.map(|p| p.to_path_buf()),
            host_counter: 0,
            host_start: SystemTime::now(),
        }
    }
}

fn he(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Substitute `#TEMPL_KEY#` placeholders in `tmpl` using `vars`. Missing
/// keys are left blank.
fn substitute(tmpl: &str, vars: &HashMap<&str, String>) -> String {
    let mut out = tmpl.to_string();
    for (k, v) in vars {
        let marker = format!("#TEMPL_{}#", k);
        out = out.replace(&marker, v);
    }
    // Any remaining #TEMPL_*# markers become empty string.
    let mut result = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(pos) = rest.find("#TEMPL_") {
        result.push_str(&rest[..pos]);
        let after = &rest[pos + 7..];
        match after.find('#') {
            Some(end) => {
                rest = &after[end + 1..];
            }
            None => {
                rest = "";
                break;
            }
        }
    }
    result.push_str(rest);
    result
}

/// Remove entire lines whose "row marker" flag was not set. The upstream
/// convention is that a line `#TEMPL_FOO_ROW#` precedes the `<tr>...</tr>`
/// row it guards; if FOO has no value, the whole row line (and its marker)
/// is dropped.
fn strip_unused_rows(rendered: &str, active: &[&str]) -> String {
    let mut lines = rendered.lines().peekable();
    let mut out = String::with_capacity(rendered.len());
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if let Some(row_name) = trimmed
            .strip_prefix("#TEMPL_")
            .and_then(|s| s.strip_suffix("_ROW#"))
        {
            let is_active = active.iter().any(|a| *a == row_name);
            if !is_active {
                // Drop the row marker AND the next <tr>...</tr> line.
                let _ = lines.next();
                continue;
            }
            // Keep the following row, drop just the marker.
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn fmt_ts(t: SystemTime) -> String {
    let d = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{d}")
}

impl ReportSink for HtmlSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Html
    }

    fn head(&mut self, _state: &GlobalState) -> Result<()> {
        self.out.write_all(TMPL_START.as_bytes())?;
        Ok(())
    }

    fn host_start(&mut self, mark: &Mark) -> Result<()> {
        self.host_counter += 1;
        self.host_start = SystemTime::now();

        let hostname = he(&mark.hostname);
        let ip = he(&mark.ip.map(|i| i.to_string()).unwrap_or_default());
        let scheme = if mark.ssl { "https" } else { "http" };
        let link_name = format!("{scheme}://{}:{}", mark.hostname, mark.port);
        let link_ip = format!(
            "{scheme}://{}:{}",
            mark.ip.map(|i| i.to_string()).unwrap_or_default(),
            mark.port
        );
        let banner = he(mark.banner.as_deref().unwrap_or(""));

        let mut vars: HashMap<&str, String> = HashMap::new();
        vars.insert("HCTR", self.host_counter.to_string());
        vars.insert("HOSTNAME", hostname);
        vars.insert("IP", ip);
        vars.insert("PORT", mark.port.to_string());
        vars.insert("BANNER", banner);
        vars.insert("LINK_NAME", he(&link_name));
        vars.insert("LINK_IP", he(&link_ip));

        let mut active_rows: Vec<&str> = Vec::new();
        if let Some(info) = &mark.ssl_info {
            if let Some(s) = &info.cert_subject {
                vars.insert("SSL_SUBJECT", he(s));
                active_rows.push("SSL_SUBJECT");
            }
            if let Some(i) = &info.cert_issuer {
                vars.insert("SSL_ISSUER", he(i));
                active_rows.push("SSL_ISSUER");
            }
            if !info.cert_alt_names.is_empty() {
                vars.insert("SSL_SAN", he(&info.cert_alt_names.join(", ")));
                active_rows.push("SSL_SAN");
            }
            if let Some(c) = &info.cipher {
                vars.insert("SSL_CIPHERS", he(c));
                active_rows.push("SSL_CIPHERS");
            }
            // CN is parsed out of subject by Perl Corvex; we just reuse subject.
            if let Some(s) = &info.cert_subject {
                vars.insert("SSL_CN", he(s));
                active_rows.push("SSL_CN");
            }
        }

        let rendered = substitute(TMPL_HEAD, &vars);
        let cleaned = strip_unused_rows(&rendered, &active_rows);
        self.out.write_all(cleaned.as_bytes())?;
        Ok(())
    }

    fn item(&mut self, mark: &Mark, item: &ReportItem) -> Result<()> {
        let mut vars: HashMap<&str, String> = HashMap::new();
        vars.insert("URI", he(&item.uri));
        vars.insert("HTTP_METHOD", he(&item.method));
        vars.insert("MSG", he(&item.message));
        vars.insert("SEVERITY", he(&item.severity.to_string()));

        let scheme = if mark.ssl { "https" } else { "http" };
        let link = format!(
            "{scheme}://{}:{}{}",
            mark.hostname, mark.port, item.uri
        );
        vars.insert("ITEM_NAME_LINK", he(&link));

        let mut active_rows: Vec<&str> = Vec::new();
        if !item.refs.is_empty() {
            vars.insert("REFERENCES", he(&item.refs));
            active_rows.push("REFERENCES");
        }
        if let Some(cve) = &item.cve {
            vars.insert("CVE", he(cve));
            active_rows.push("CVE");
        }

        let rendered = substitute(TMPL_ITEM, &vars);
        let cleaned = strip_unused_rows(&rendered, &active_rows);
        self.out.write_all(cleaned.as_bytes())?;
        Ok(())
    }

    fn host_end(&mut self, mark: &Mark) -> Result<()> {
        let mut vars: HashMap<&str, String> = HashMap::new();
        vars.insert("START", fmt_ts(self.host_start));
        vars.insert("END", fmt_ts(SystemTime::now()));
        let elapsed = SystemTime::now()
            .duration_since(self.host_start)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        vars.insert("ELAPSED", elapsed.to_string());
        vars.insert(
            "STATISTICS",
            format!(
                "{} findings, {} errors",
                mark.counters.vulns(),
                mark.counters.errors()
            ),
        );
        self.out
            .write_all(substitute(TMPL_END, &vars).as_bytes())?;
        Ok(())
    }

    fn summary(&mut self, state: &GlobalState) -> Result<()> {
        let mut vars: HashMap<&str, String> = HashMap::new();
        vars.insert("CORVEX_VER", corvex_core::VERSION.to_string());
        vars.insert("CORVEX_CLI", std::env::args().collect::<Vec<_>>().join(" "));
        vars.insert(
            "CORVEX_HOSTS_TESTED",
            state.hosts_completed.load(Ordering::Relaxed).to_string(),
        );
        vars.insert(
            "SCAN_START",
            state.scan_start.load(Ordering::Relaxed).to_string(),
        );
        vars.insert(
            "SCAN_END",
            state.scan_end.load(Ordering::Relaxed).to_string(),
        );
        vars.insert(
            "SCAN_ELAPSED",
            format!("{}s", state.elapsed_secs()),
        );
        self.out
            .write_all(substitute(TMPL_SUMMARY, &vars).as_bytes())?;
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.out.write_all(TMPL_CLOSE.as_bytes())?;
        self.out.flush()?;
        Ok(())
    }
}
