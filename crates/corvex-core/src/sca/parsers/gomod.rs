//! go.mod parser for Go dependencies.

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct GoModParser;

impl ManifestParser for GoModParser {
    fn file_names(&self) -> &[&str] {
        &["go.mod", "go.sum"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "go.sum" {
            parse_go_sum(path)
        } else {
            parse_go_mod(path)
        }
    }
}

fn parse_go_mod(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let mut components = Vec::new();
    let mut in_require = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "require (" {
            in_require = true;
            continue;
        }
        if trimmed == ")" {
            in_require = false;
            continue;
        }

        // Single-line require: `require github.com/pkg/errors v0.9.1`
        if let Some(rest) = trimmed.strip_prefix("require ") {
            if !rest.starts_with('(') {
                if let Some(comp) = parse_go_dep(rest, path) {
                    components.push(comp);
                }
            }
        } else if in_require {
            // Inside require block
            if let Some(comp) = parse_go_dep(trimmed, path) {
                components.push(comp);
            }
        }
    }

    Ok(components)
}

fn parse_go_sum(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let mut components = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let module = parts[0];
            let version = parts[1].split('/').next().unwrap_or(parts[1]);
            let version = version.trim_start_matches('v');
            let key = format!("{}@{}", module, version);
            if !version.is_empty() && seen.insert(key) {
                components.push(
                    Component::new(module, version, Ecosystem::Go).with_source(path.to_path_buf()),
                );
            }
        }
    }

    Ok(components)
}

fn parse_go_dep(line: &str, path: &Path) -> Option<Component> {
    let line = line.split("//").next()?.trim();
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        let module = parts[0];
        let version = parts[1].trim_start_matches('v');
        // Skip indirect dependencies marked with // indirect
        if !module.is_empty() && !version.is_empty() {
            return Some(
                Component::new(module, version, Ecosystem::Go).with_source(path.to_path_buf()),
            );
        }
    }
    None
}
