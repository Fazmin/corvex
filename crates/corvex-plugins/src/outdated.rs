//! Outdated server version detection via `db_outdated` regex matching.

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
    name: "outdated",
    full_name: "Outdated Software",
    description: "Check Server banner against the db_outdated database.",
    weight: 30,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

#[derive(Default)]
pub struct OutdatedPlugin;

#[async_trait]
impl Plugin for OutdatedPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_postfetch(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        req: &Request,
        resp: &Response,
    ) -> Result<Vec<ReportItem>> {
        // Only fire once per mark.
        {
            let m = mark.lock().await;
            if m.counters.errors() == u64::MAX {
                return Ok(Vec::new());
            }
        }
        let server = match resp.header("server") {
            Some(s) => s.to_string(),
            None => return Ok(Vec::new()),
        };
        let mut items = Vec::new();
        for row in &ctx.dbs.outdated.rows {
            let rx = match Regex::new(&row.server_regex) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if rx.is_match(&server) {
                let msg = row
                    .message
                    .replace("@RUNNING_VER", &server)
                    .replace("@CURRENT_VER", &row.version);
                items.push(ReportItem {
                    corvex_id: row.id.clone(),
                    method: req.method.clone(),
                    uri: req.uri.clone(),
                    message: msg,
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                });
                // Report at most the first match to mirror Perl behavior.
                break;
            }
        }
        Ok(items)
    }
}
