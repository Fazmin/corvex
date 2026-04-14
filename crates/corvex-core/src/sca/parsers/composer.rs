//! composer.lock parser for PHP dependencies.

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct ComposerParser;

impl ManifestParser for ComposerParser {
    fn file_names(&self) -> &[&str] {
        &["composer.lock"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

        let json: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| format!("json parse: {e}"))?;

        let mut components = Vec::new();

        // composer.lock has "packages" and "packages-dev" arrays
        for section in ["packages", "packages-dev"] {
            if let Some(packages) = json.get(section).and_then(|p| p.as_array()) {
                for pkg in packages {
                    let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let version = pkg
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim_start_matches('v');
                    if !name.is_empty() && !version.is_empty() {
                        let mut comp = Component::new(name, version, Ecosystem::Packagist);
                        comp.source_file = Some(path.to_path_buf());
                        comp.license = pkg
                            .get("license")
                            .and_then(|l| l.as_array())
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        comp.description = pkg
                            .get("description")
                            .and_then(|d| d.as_str())
                            .map(|s| s.to_string());
                        components.push(comp);
                    }
                }
            }
        }

        Ok(components)
    }
}
