//! Gemfile.lock parser for Ruby dependencies.

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct GemfileParser;

impl ManifestParser for GemfileParser {
    fn file_names(&self) -> &[&str] {
        &["Gemfile.lock"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

        let mut components = Vec::new();
        let mut in_specs = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // The "specs:" section under GEM contains the resolved gems
            if trimmed == "specs:" {
                in_specs = true;
                continue;
            }

            // Empty line or new section header ends specs
            if in_specs && (trimmed.is_empty() || (!line.starts_with(' ') && !line.starts_with('\t'))) {
                in_specs = false;
                continue;
            }

            if in_specs {
                // Gem entries are indented with 4 spaces: "    gem_name (version)"
                // Sub-dependencies have 6+ spaces
                let indent = line.len() - line.trim_start().len();
                if indent == 4 {
                    if let Some((name, version)) = parse_gem_line(trimmed) {
                        components.push(
                            Component::new(&name, &version, Ecosystem::RubyGems)
                                .with_source(path.to_path_buf()),
                        );
                    }
                }
            }
        }

        Ok(components)
    }
}

/// Parse a gem spec line like "rails (7.0.4)" into (name, version).
fn parse_gem_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let paren_start = line.find('(')?;
    let paren_end = line.find(')')?;
    if paren_start >= paren_end {
        return None;
    }
    let name = line[..paren_start].trim().to_string();
    let version = line[paren_start + 1..paren_end].trim().to_string();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}
