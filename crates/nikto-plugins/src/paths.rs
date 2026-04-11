use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "paths",
    full_name: "Path Extraction",
    description: "Harvest URL paths from responses for variables.",
    weight: 50,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

#[derive(Default)]
pub struct PathsPlugin;

#[async_trait]
impl Plugin for PathsPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
