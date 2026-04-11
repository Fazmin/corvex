use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "shellshock",
    full_name: "Shellshock",
    description: "CVE-2014-6271 ShellShock detection.",
    weight: 70,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct ShellshockPlugin;

#[async_trait]
impl Plugin for ShellshockPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
