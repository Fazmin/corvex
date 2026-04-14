//! Markdown report sink — outputs structured `.md` files.

use corvex_core::report::{ReportFormat, ReportItem, ReportSink, Severity};
use corvex_core::state::GlobalState;
use corvex_core::target::Mark;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering;

pub struct MarkdownSink {
    output: Option<Box<dyn Write + Send>>,
    items: Vec<(String, ReportItem)>, // (host_ident, item)
    current_host: String,
}

impl MarkdownSink {
    pub fn new(output: Option<&Path>) -> Self {
        let writer: Option<Box<dyn Write + Send>> = output.map(|p| {
            Box::new(
                std::fs::File::create(p).expect("failed to create markdown output file"),
            ) as Box<dyn Write + Send>
        });
        Self {
            output: writer,
            items: Vec::new(),
            current_host: String::new(),
        }
    }

    fn write_str(&mut self, s: &str) {
        if let Some(ref mut w) = self.output {
            let _ = w.write_all(s.as_bytes());
        } else {
            print!("{}", s);
        }
    }
}

impl ReportSink for MarkdownSink {
    fn format(&self) -> ReportFormat {
        ReportFormat::Markdown
    }

    fn head(&mut self, state: &GlobalState) -> corvex_core::Result<()> {
        let _ = state;
        self.write_str("# Corvex Scan Report\n\n");
        self.write_str(&format!(
            "**Generated:** {}\n\n",
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        ));
        self.write_str("---\n\n");
        Ok(())
    }

    fn host_start(&mut self, mark: &Mark) -> corvex_core::Result<()> {
        self.current_host = mark.ident.clone();
        let scheme = if mark.ssl { "https" } else { "http" };
        self.write_str(&format!(
            "## Target: {}://{}:{}\n\n",
            scheme, mark.hostname, mark.port
        ));
        if let Some(ref banner) = mark.banner {
            self.write_str(&format!("**Server:** {}\n\n", banner));
        }
        Ok(())
    }

    fn ssl_info(&mut self, mark: &Mark) -> corvex_core::Result<()> {
        if let Some(ref info) = mark.ssl_info {
            self.write_str("### TLS Information\n\n");
            if let Some(ref proto) = info.protocol {
                self.write_str(&format!("- **Protocol:** {}\n", proto));
            }
            if let Some(ref cipher) = info.cipher {
                self.write_str(&format!("- **Cipher:** {}\n", cipher));
            }
            if let Some(ref subject) = info.cert_subject {
                self.write_str(&format!("- **Subject:** {}\n", subject));
            }
            if let Some(ref issuer) = info.cert_issuer {
                self.write_str(&format!("- **Issuer:** {}\n", issuer));
            }
            self.write_str("\n");
        }
        Ok(())
    }

    fn item(&mut self, _mark: &Mark, item: &ReportItem) -> corvex_core::Result<()> {
        self.items
            .push((self.current_host.clone(), item.clone()));
        Ok(())
    }

    fn host_end(&mut self, _mark: &Mark) -> corvex_core::Result<()> {
        // Collect output strings first, then write them
        let host = self.current_host.clone();
        let host_items: Vec<ReportItem> = self
            .items
            .iter()
            .filter(|(h, _)| h == &host)
            .map(|(_, item)| item.clone())
            .collect();

        if host_items.is_empty() {
            self.write_str("*No findings for this target.*\n\n");
            return Ok(());
        }

        let mut buf = String::new();
        buf.push_str("### Findings\n\n");
        buf.push_str("| Severity | ID | Method | URI | Description |\n");
        buf.push_str("|----------|-----|--------|-----|-------------|\n");

        for item in &host_items {
            let sev_badge = match item.severity {
                Severity::Critical => "**CRITICAL**",
                Severity::High => "**HIGH**",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
                Severity::Info => "INFO",
            };

            let desc = item.message.replace('|', "\\|");
            let desc = if desc.len() > 120 {
                format!("{}...", &desc[..120])
            } else {
                desc
            };

            buf.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                sev_badge,
                item.corvex_id,
                item.method,
                item.uri,
                desc,
            ));
        }

        // SCA-specific details (CVE, EPSS, fix info)
        let sca_items: Vec<_> = host_items
            .iter()
            .filter(|i| i.cve.is_some())
            .collect();

        if !sca_items.is_empty() {
            buf.push_str("\n### Vulnerability Details\n\n");
            for item in sca_items {
                if let Some(ref cve) = item.cve {
                    buf.push_str(&format!("#### {}\n\n", cve));
                    buf.push_str(&format!("- **Component:** {}\n",
                        item.component.as_deref().unwrap_or("N/A")));
                    if let Some(cvss) = item.cvss {
                        buf.push_str(&format!("- **CVSS:** {:.1}\n", cvss));
                    }
                    if let Some(epss) = item.epss_score {
                        buf.push_str(&format!("- **EPSS:** {:.4} ({:.1}%)\n",
                            epss, item.epss_percentile.unwrap_or(0.0) * 100.0));
                    }
                    if let Some(ref fix) = item.fix_version {
                        buf.push_str(&format!("- **Fix available:** {}\n", fix));
                    }
                    buf.push('\n');
                }
            }
        }

        buf.push_str("\n---\n\n");
        self.write_str(&buf);
        Ok(())
    }

    fn summary(&mut self, state: &GlobalState) -> corvex_core::Result<()> {
        // Severity breakdown
        let mut critical = 0u32;
        let mut high = 0u32;
        let mut medium = 0u32;
        let mut low = 0u32;
        let mut info = 0u32;

        for (_, item) in &self.items {
            match item.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info += 1,
            }
        }

        let mut buf = String::new();
        buf.push_str("## Summary\n\n");
        buf.push_str(&format!(
            "- **Total requests:** {}\n",
            state.total_requests.load(Ordering::Relaxed)
        ));
        buf.push_str(&format!(
            "- **Total findings:** {}\n",
            state.total_findings.load(Ordering::Relaxed)
        ));
        buf.push_str(&format!(
            "- **Errors:** {}\n",
            state.total_errors.load(Ordering::Relaxed)
        ));
        buf.push_str(&format!(
            "- **Severity breakdown:** {} critical, {} high, {} medium, {} low, {} info\n",
            critical, high, medium, low, info
        ));
        buf.push_str(&format!(
            "\n*Scan completed in {}s*\n",
            state.elapsed_secs()
        ));

        self.write_str(&buf);
        Ok(())
    }

    fn close(&mut self) -> corvex_core::Result<()> {
        if let Some(ref mut w) = self.output {
            let _ = w.flush();
        }
        Ok(())
    }
}
