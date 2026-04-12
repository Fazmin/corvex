use async_trait::async_trait;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "siebel",
    full_name: "Siebel Checks",
    description: "Siebel-specific checks (standalone).",
    weight: 80,
    default: false,
    extra: true,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct SiebelPlugin;

#[async_trait]
impl Plugin for SiebelPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
