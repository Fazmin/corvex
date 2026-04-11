use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "apacheusers",
    full_name: "Apache Users",
    description: "Enumerate Apache mod_userdir accounts.",
    weight: 60,
    default: false,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct ApacheUsersPlugin;

#[async_trait]
impl Plugin for ApacheUsersPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
