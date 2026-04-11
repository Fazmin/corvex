use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "put_del_test",
    full_name: "PUT/DELETE Test",
    description: "Test whether PUT and DELETE methods succeed.",
    weight: 65,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct PutDelPlugin;

#[async_trait]
impl Plugin for PutDelPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
