//! Save HTTP responses to disk when `-Save` is set. Each response lands in
//! `<save_dir>/<host>-<port>/<sanitized-uri>.txt` as the raw body.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "fileops",
    full_name: "File Operations",
    description: "Save responses to disk when --Save is set.",
    weight: 50,
    default: false,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

#[derive(Default)]
pub struct FileopsPlugin;

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect()
}

#[async_trait]
impl Plugin for FileopsPlugin {
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
        let save_dir = match ctx.cli.save.as_ref() {
            Some(d) => d.clone(),
            None => return Ok(Vec::new()),
        };
        let host_dir: PathBuf = {
            let m = mark.lock().await;
            save_dir.join(format!("{}-{}", m.hostname, m.port))
        };
        let _ = fs::create_dir_all(&host_dir);
        let filename = format!(
            "{}-{}.txt",
            req.method.to_ascii_lowercase(),
            sanitize(req.uri.trim_start_matches('/'))
        );
        let path = host_dir.join(filename);
        let _ = fs::write(&path, &resp.body);
        Ok(Vec::new())
    }
}
