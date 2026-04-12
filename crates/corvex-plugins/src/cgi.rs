//! CGI directory enumeration. Probes `@CGIDIRS` entries from db_variables
//! and reports any directory that returns something other than a 404.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "cgi",
    full_name: "CGI Directories",
    description: "Enumerate CGI directories from db_variables (@CGIDIRS).",
    weight: 50,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct CgiPlugin;

#[async_trait]
impl Plugin for CgiPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let dirs: Vec<String> = ctx
            .dbs
            .variables
            .entries
            .iter()
            .find(|(n, _)| n == "CGIDIRS")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let mut findings = Vec::new();
        for dir in dirs {
            let mut req = {
                let m = mark.lock().await;
                Request::new(&m.hostname, m.port, "GET", &dir)
            };
            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if resp.status != 404 && resp.status != 410 {
                findings.push(ReportItem {
                    corvex_id: format!("CGI-DIR-{}", resp.status),
                    method: "GET".into(),
                    uri: dir.clone(),
                    message: format!("CGI directory responded with {}", resp.status),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                });
            }
        }
        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }
        Ok(())
    }
}
