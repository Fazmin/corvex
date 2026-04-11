use async_trait::async_trait;
use nikto_core::error::Result;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};
use nikto_core::scan::ScanCtx;
use nikto_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "auth",
    full_name: "HTTP Authentication",
    description: "Detect and report HTTP authentication realms.",
    weight: 40,
    default: true,
    extra: false,
    hooks: &[HookKind::Start, HookKind::Postfetch],
};

#[derive(Default)]
pub struct AuthPlugin;

#[async_trait]
impl Plugin for AuthPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_start(&self, _ctx: &ScanCtx, _mark: Arc<Mutex<Mark>>) -> Result<()> {
        Ok(())
    }
}
