use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "cgi",
    full_name: "CGI Directories",
    description: "Enumerate CGI directories.",
    weight: 50,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct CgiPlugin;

#[async_trait]
impl Plugin for CgiPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
