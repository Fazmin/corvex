use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "ms10_070",
    full_name: "MS10-070",
    description: "Check for ASP.NET MS10-070 padding-oracle weakness.",
    weight: 70,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct Ms10_070Plugin;

#[async_trait]
impl Plugin for Ms10_070Plugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
