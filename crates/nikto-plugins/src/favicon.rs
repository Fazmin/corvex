//! Favicon fingerprinting via db_favicon MD5 hash.

use async_trait::async_trait;
use md5::{Digest, Md5};
use nikto_core::error::Result;
use nikto_core::http::request::Request;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};
use nikto_core::report::ReportItem;
use nikto_core::scan::ScanCtx;
use nikto_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "favicon",
    full_name: "Favicon",
    description: "Fingerprint server software via /favicon.ico hash.",
    weight: 55,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct FaviconPlugin;

#[async_trait]
impl Plugin for FaviconPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut req = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "GET", "/favicon.ico")
        };
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if resp.status != 200 || resp.body.is_empty() {
            return Ok(());
        }
        let mut h = Md5::new();
        h.update(&resp.body);
        let digest = format!("{:x}", h.finalize());
        for row in &ctx.dbs.favicon.rows {
            if row.md5.eq_ignore_ascii_case(&digest) {
                ctx.emit(
                    mark.clone(),
                    vec![ReportItem {
                        nikto_id: row.id.clone(),
                        method: "GET".into(),
                        uri: "/favicon.ico".into(),
                        message: format!(
                            "Identified favicon ({}) as {}",
                            digest, row.description
                        ),
                        refs: String::new(),
                        data: String::new(),
                        plugin: INFO.name.to_string(),
                    }],
                )
                .await;
                break;
            }
        }
        Ok(())
    }
}
