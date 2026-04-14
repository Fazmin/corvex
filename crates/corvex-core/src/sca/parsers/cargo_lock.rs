//! Cargo.lock parser for Rust dependencies.

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct CargoLockParser;

impl ManifestParser for CargoLockParser {
    fn file_names(&self) -> &[&str] {
        &["Cargo.lock"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

        let mut components = Vec::new();
        let mut name: Option<String> = None;
        let mut version: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();

            if line == "[[package]]" {
                // Emit previous package if complete
                if let (Some(n), Some(v)) = (name.take(), version.take()) {
                    components.push(
                        Component::new(&n, &v, Ecosystem::Cargo).with_source(path.to_path_buf()),
                    );
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("name = ") {
                name = Some(strip_toml_string(rest));
            } else if let Some(rest) = line.strip_prefix("version = ") {
                version = Some(strip_toml_string(rest));
            }
        }

        // Emit last package
        if let (Some(n), Some(v)) = (name, version) {
            components
                .push(Component::new(&n, &v, Ecosystem::Cargo).with_source(path.to_path_buf()));
        }

        Ok(components)
    }
}

fn strip_toml_string(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}
