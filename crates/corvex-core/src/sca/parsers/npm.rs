//! package-lock.json and yarn.lock parsers for JavaScript/Node.js dependencies.

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct NpmParser;

impl ManifestParser for NpmParser {
    fn file_names(&self) -> &[&str] {
        &["package-lock.json", "yarn.lock"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if name == "yarn.lock" {
            parse_yarn_lock(path)
        } else {
            parse_package_lock(path)
        }
    }
}

fn parse_package_lock(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("json parse: {e}"))?;

    let mut components = Vec::new();

    // package-lock.json v2/v3 format: "packages" object
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in packages {
            // Skip the root package (empty key or ".")
            if key.is_empty() || key == "." {
                continue;
            }
            // Extract name from the key (node_modules/name or node_modules/@scope/name)
            let pkg_name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key)
                .to_string();
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !pkg_name.is_empty() && !version.is_empty() {
                components.push(
                    Component::new(&pkg_name, &version, Ecosystem::Npm)
                        .with_source(path.to_path_buf()),
                );
            }
        }
    }
    // package-lock.json v1 format: "dependencies" object
    else if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        parse_npm_deps_recursive(deps, path, &mut components);
    }

    Ok(components)
}

fn parse_npm_deps_recursive(
    deps: &serde_json::Map<String, serde_json::Value>,
    path: &Path,
    components: &mut Vec<Component>,
) {
    for (name, val) in deps {
        let version = val
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !version.is_empty() {
            components.push(
                Component::new(name, &version, Ecosystem::Npm).with_source(path.to_path_buf()),
            );
        }
        // Recurse into nested dependencies
        if let Some(nested) = val.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_deps_recursive(nested, path, components);
        }
    }
}

fn parse_yarn_lock(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let mut components = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        // Package header lines look like: "express@^4.18.0, express@~4.18.2":
        // or: express@^4.18.0:
        if !line.starts_with(' ') && !line.starts_with('#') && line.contains('@') && line.ends_with(':') {
            let header = line.trim_end_matches(':').trim_matches('"');
            // Take the first specifier and extract the name
            if let Some(spec) = header.split(',').next() {
                let spec = spec.trim().trim_matches('"');
                // Find the last @ that separates name from version spec
                if let Some(at_pos) = spec.rfind('@') {
                    if at_pos > 0 {
                        current_name = Some(spec[..at_pos].to_string());
                    }
                }
            }
        }
        // Version line: "  version "1.2.3""
        if let Some(ref name) = current_name {
            let trimmed = line.trim();
            if let Some(ver_str) = trimmed.strip_prefix("version ") {
                let version = ver_str.trim().trim_matches('"').to_string();
                if !version.is_empty() {
                    components.push(
                        Component::new(name, &version, Ecosystem::Npm)
                            .with_source(path.to_path_buf()),
                    );
                }
                current_name = None;
            }
        }
    }

    Ok(components)
}
