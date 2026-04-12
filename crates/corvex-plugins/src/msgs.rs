//! Banner / server message matching (db_server_msgs).

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
    name: "msgs",
    full_name: "Server Messages",
    description: "Match the Server banner against db_server_msgs.",
    weight: 35,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

#[derive(Default)]
pub struct MsgsPlugin;

#[async_trait]
impl Plugin for MsgsPlugin {
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
        if req.uri != "/" {
            return Ok(Vec::new());
        }
        let server = match resp.header("server") {
            Some(s) => s.to_string(),
            None => return Ok(Vec::new()),
        };
        let mut items = Vec::new();
        for row in &ctx.dbs.server_msgs.rows {
            let rx = match Regex::new(&row.server_regex) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if rx.is_match(&server) {
                items.push(ReportItem {
                    corvex_id: row.id.clone(),
                    method: req.method.clone(),
                    uri: req.uri.clone(),
                    message: row.message.clone(),
                    refs: row.reference.clone(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                });
            }
        }
        Ok(items)
    }
}
