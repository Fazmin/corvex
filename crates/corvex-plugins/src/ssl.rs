//! Report TLS handshake + certificate metadata as findings once per host.
//!
//! The HTTP client extracts the cert/cipher/protocol on the initial fetch
//! and stashes them in `mark.ssl_info`. This plugin fires on the Start hook
//! and emits a summary finding so every report sink sees it.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "ssl",
    full_name: "SSL/TLS",
    description: "Report TLS certificate, cipher, and protocol information.",
    weight: 10,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct SslPlugin;

#[async_trait]
impl Plugin for SslPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let info = {
            let m = mark.lock().await;
            m.ssl_info.clone()
        };
        let info = match info {
            Some(i) => i,
            None => return Ok(()),
        };

        let mut parts: Vec<String> = Vec::new();
        if let Some(p) = &info.protocol {
            parts.push(format!("Protocol: {p}"));
        }
        if let Some(c) = &info.cipher {
            parts.push(format!("Cipher: {c}"));
        }
        if let Some(s) = &info.cert_subject {
            parts.push(format!("Subject: {s}"));
        }
        if let Some(s) = &info.cert_issuer {
            parts.push(format!("Issuer: {s}"));
        }
        if !info.cert_alt_names.is_empty() {
            parts.push(format!("SAN: {}", info.cert_alt_names.join(", ")));
        }
        if let Some(s) = &info.cert_not_after {
            parts.push(format!("Not After: {s}"));
        }

        if parts.is_empty() {
            return Ok(());
        }

        ctx.emit(
            mark,
            vec![ReportItem {
                corvex_id: "SSL-INFO".into(),
                method: "GET".into(),
                uri: "/".into(),
                message: parts.join(" | "),
                refs: String::new(),
                data: String::new(),
                plugin: INFO.name.to_string(),
                ..Default::default()
            }],
        )
        .await;
        Ok(())
    }
}
