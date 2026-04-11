use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "optionsbleed",
    full_name: "Optionsbleed",
    description: "Probe CVE-2017-9798 Optionsbleed on Apache.",
    weight: 75,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct OptionsbleedPlugin;

#[async_trait]
impl Plugin for OptionsbleedPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
