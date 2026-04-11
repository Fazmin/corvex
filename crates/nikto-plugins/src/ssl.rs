//! SSL / TLS certificate reporting (stub — SslInfo is populated by the
//! HTTP client; this plugin surfaces it to the report sinks via a finding).

use async_trait::async_trait;
use nikto_core::error::Result;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};
use nikto_core::scan::ScanCtx;
use nikto_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "ssl",
    full_name: "SSL/TLS",
    description: "Report TLS certificate and cipher information.",
    weight: 10,
    default: true,
    extra: false,
    hooks: &[HookKind::Start],
};

#[derive(Default)]
pub struct SslPlugin;

#[async_trait]
impl Plugin for SslPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_start(&self, _ctx: &ScanCtx, _mark: Arc<Mutex<Mark>>) -> Result<()> {
        // Placeholder: full cert extraction lives in http::tls. This hook
        // exists so the plugin registry has an ordering slot for SSL ops.
        Ok(())
    }
}
