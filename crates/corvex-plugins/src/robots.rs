//! robots.txt discovery — fetch and enumerate each Disallow path.

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
    name: "robots",
    full_name: "Robots Checks",
    description: "Retrieve robots.txt and report every Disallow entry.",
    weight: 49,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct RobotsPlugin;

#[async_trait]
impl Plugin for RobotsPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut req = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "GET", "/robots.txt")
        };
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if resp.status != 200 {
            return Ok(());
        }
        let text = resp.body_str();
        let mut entries = Vec::new();
        for line in text.lines() {
            let lower = line.trim_start().to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("disallow:") {
                let path = rest.trim().to_string();
                if !path.is_empty() {
                    entries.push(path);
                }
            }
        }
        if entries.is_empty() {
            return Ok(());
        }
        let msg = format!(
            "robots.txt contains {} entries which should be manually viewed.",
            entries.len()
        );
        ctx.emit(
            mark.clone(),
            vec![ReportItem {
                corvex_id: "ROBOTS".into(),
                method: "GET".into(),
                uri: "/robots.txt".into(),
                message: msg,
                refs: String::new(),
                data: entries.join("\n"),
                plugin: INFO.name.to_string(),
            }],
        )
        .await;
        Ok(())
    }
}
