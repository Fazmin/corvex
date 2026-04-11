use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "sitefiles",
    full_name: "Site Files",
    description: "Probe for site-specific backup / config files.",
    weight: 60,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct SitefilesPlugin;

#[async_trait]
impl Plugin for SitefilesPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
