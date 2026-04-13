//! Extract URL paths from response bodies (href, src, action attributes).
//!
//! The upstream Perl plugin feeds these into the `@PATHS` variable for
//! reuse by other tests. Here we simply emit an informational finding
//! when interesting paths appear on the root page.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "paths",
    full_name: "Path Extraction",
    description: "Harvest URL paths from HTML attributes on the root page.",
    weight: 50,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

static LINK_RX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["']?([^"'\s>]+)"#).unwrap()
});

#[derive(Default)]
pub struct PathsPlugin;

#[async_trait]
impl Plugin for PathsPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_postfetch(
        &self,
        _ctx: &ScanCtx,
        _mark: Arc<Mutex<Mark>>,
        req: &Request,
        resp: &Response,
    ) -> Result<Vec<ReportItem>> {
        if req.uri != "/" || resp.status != 200 {
            return Ok(Vec::new());
        }
        let body = resp.body_str();
        let mut paths: BTreeSet<String> = BTreeSet::new();
        for cap in LINK_RX.captures_iter(&body) {
            let val = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            if val.starts_with('#') || val.starts_with("mailto:") || val.starts_with("javascript:")
            {
                continue;
            }
            paths.insert(val.to_string());
        }
        if paths.len() >= 5 {
            let sample: Vec<String> = paths.iter().take(20).cloned().collect();
            return Ok(vec![ReportItem {
                corvex_id: "PATHS".into(),
                method: req.method.clone(),
                uri: req.uri.clone(),
                message: format!(
                    "Extracted {} link/src/action targets from the root page.",
                    paths.len()
                ),
                refs: String::new(),
                data: sample.join("\n"),
                plugin: INFO.name.to_string(),
                ..Default::default()
            }]);
        }
        Ok(Vec::new())
    }
}
