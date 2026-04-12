use async_trait::async_trait;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};

static INFO: PluginInfo = PluginInfo {
    name: "dictionary_attack",
    full_name: "Dictionary Attack",
    description: "Probe paths from db_dictionary.",
    weight: 20,
    default: false,
    extra: true,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct DictionaryAttackPlugin;

#[async_trait]
impl Plugin for DictionaryAttackPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }
}
