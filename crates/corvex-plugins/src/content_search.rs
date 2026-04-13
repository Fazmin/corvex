//! Content-based pattern scanning (db_content_search).

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use regex::Regex;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "content_search",
    full_name: "Content Search",
    description: "Match response bodies against db_content_search patterns.",
    weight: 45,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

#[derive(Default)]
pub struct ContentSearchPlugin;

#[async_trait]
impl Plugin for ContentSearchPlugin {
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
        let body = resp.body_str();
        let mut items = Vec::new();
        for row in &ctx.dbs.content_search.rows {
            let rx = match Regex::new(&row.matchstring) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Some(cap) = rx.captures(&body) {
                let replaced = if row.message.contains("$1") {
                    row.message.replace(
                        "$1",
                        cap.get(1).map(|m| m.as_str()).unwrap_or(""),
                    )
                } else {
                    row.message.clone()
                };
                items.push(ReportItem {
                    corvex_id: row.id.clone(),
                    method: req.method.clone(),
                    uri: req.uri.clone(),
                    message: replaced,
                    refs: row.references.clone(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    ..Default::default()
                });
            }
        }
        Ok(items)
    }
}
