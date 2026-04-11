use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "negotiate",
    full_name: "mod_negotiate",
    description: "Check for Apache mod_negotiate enumeration.",
    weight: 60,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct NegotiatePlugin;

#[async_trait]
impl Plugin for NegotiatePlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
