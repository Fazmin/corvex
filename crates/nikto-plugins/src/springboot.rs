use async_trait::async_trait;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "springboot",
    full_name: "Spring Boot Actuator",
    description: "Probe Spring Boot actuator endpoints.",
    weight: 70,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct SpringbootPlugin;

#[async_trait]
impl Plugin for SpringbootPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
