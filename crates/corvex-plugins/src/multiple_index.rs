//! Probe the target root for multiple default index files (`index.html`,
//! `index.php`, `default.asp`, …). Anything returning 200 that isn't the
//! same as the baseline `/` response is reported.

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
    name: "multiple_index",
    full_name: "Multiple Index Files",
    description: "Find multiple default index files by brute-forcing db_multiple_index.",
    weight: 55,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct MultipleIndexPlugin;

#[async_trait]
impl Plugin for MultipleIndexPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut found = Vec::new();
        for name in &ctx.dbs.multiple_index.names {
            let uri = format!("/{name}");
            let mut req = {
                let m = mark.lock().await;
                Request::new(&m.hostname, m.port, "GET", &uri)
            };
            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if resp.status == 200 {
                found.push(uri);
            }
        }
        if found.len() > 1 {
            let msg = format!(
                "Multiple index files present ({}). Having more than one default document can reveal backend technology.",
                found.join(", ")
            );
            ctx.emit(
                mark.clone(),
                vec![ReportItem {
                    corvex_id: "MULTI-INDEX".into(),
                    method: "GET".into(),
                    uri: "/".into(),
                    message: msg,
                    refs: String::new(),
                    data: found.join("\n"),
                    plugin: INFO.name.to_string(),
                    ..Default::default()
                }],
            )
            .await;
        }
        Ok(())
    }
}
