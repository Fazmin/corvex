//! Curated map of `plugin_name → [template_id, ...]` used to suppress
//! Nuclei templates whose detection is already covered by a native
//! corvex plugin. Loaded from `program/databases/nuclei/overlap.toml`.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct OverlapMap {
    /// plugin name → list of nuclei template ids to suppress when that
    /// plugin is enabled.
    #[serde(default)]
    pub by_plugin: HashMap<String, Vec<String>>,
}

impl OverlapMap {
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let parsed: OverlapMap = toml_crate::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(parsed)
    }

    /// Template ids to skip given the set of currently-enabled plugin
    /// names. A plugin absent from the map contributes nothing.
    pub fn skip_for_enabled(&self, enabled: &HashSet<&str>) -> HashSet<String> {
        let mut out = HashSet::new();
        for (plugin, ids) in &self.by_plugin {
            if enabled.contains(plugin.as_str()) {
                out.extend(ids.iter().cloned());
            }
        }
        out
    }
}
