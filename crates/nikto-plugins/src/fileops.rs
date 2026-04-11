use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "fileops",
    full_name: "File Operations",
    description: "Save responses and compute checksums.",
    weight: 50,
    default: false,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

#[derive(Default)]
pub struct FileopsPlugin;

#[async_trait]
impl Plugin for FileopsPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
