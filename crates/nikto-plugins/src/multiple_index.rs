use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "multiple_index",
    full_name: "Multiple Index Files",
    description: "Find multiple default index files.",
    weight: 55,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct MultipleIndexPlugin;

#[async_trait]
impl Plugin for MultipleIndexPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
