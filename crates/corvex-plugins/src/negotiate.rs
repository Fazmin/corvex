//! Apache mod_negotiation check: if the server returns a Content-Location
//! header or "300 Multiple Choices" for an extensionless file, content
//! negotiation is enabled and can be used to enumerate files.

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
    name: "negotiate",
    full_name: "mod_negotiate",
    description: "Detect Apache mod_negotiation (Content-Location / 300).",
    weight: 60,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct NegotiatePlugin;

#[async_trait]
impl Plugin for NegotiatePlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        // Try a probe that is likely to trigger negotiation: a bare "index"
        // with Accept for multiple types.
        let mut req = {
            let m = mark.lock().await;
            let mut r = Request::new(&m.hostname, m.port, "GET", "/index");
            r.set_header("Accept", "text/html, text/plain;q=0.9, */*;q=0.5");
            r
        };
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let has_cloc = resp.header("content-location").is_some();
        let has_alt = resp.header("alternates").is_some();
        if resp.status == 300 || has_cloc || has_alt {
            ctx.emit(
                mark,
                vec![ReportItem {
                    corvex_id: "MOD-NEGOTIATE".into(),
                    method: "GET".into(),
                    uri: "/index".into(),
                    message: "Apache mod_negotiation is enabled — content negotiation can be used to enumerate files on the server.".into(),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                }],
            )
            .await;
        }
        Ok(())
    }
}
