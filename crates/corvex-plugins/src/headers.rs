//! Header analysis. Reports missing recommended security headers.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "headers",
    full_name: "HTTP Headers",
    description: "Analyze HTTP response headers for security flags.",
    weight: 20,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

#[derive(Default)]
pub struct HeadersPlugin;

#[async_trait]
impl Plugin for HeadersPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_postfetch(
        &self,
        ctx: &ScanCtx,
        _mark: Arc<Mutex<Mark>>,
        req: &Request,
        resp: &Response,
    ) -> Result<Vec<ReportItem>> {
        // Only fire the missing-header check on the root page fetch.
        if req.uri != "/" {
            return Ok(Vec::new());
        }
        let mut items = Vec::new();
        for row in &ctx.dbs.headers_suggested.rows {
            if resp.header(&row.header).is_none() {
                items.push(ReportItem {
                    corvex_id: format!("H-{}", row.header),
                    method: req.method.clone(),
                    uri: req.uri.clone(),
                    message: format!(
                        "The {} header is not set. See {}",
                        row.header, row.reference
                    ),
                    refs: row.reference.clone(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::Low,
                    ..Default::default()
                });
            }
        }
        Ok(items)
    }
}
