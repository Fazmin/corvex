//! Python dependency file parsers (requirements.txt, Pipfile.lock).

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct PythonParser;

impl ManifestParser for PythonParser {
    fn file_names(&self) -> &[&str] {
        &["requirements.txt", "Pipfile.lock"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if name == "Pipfile.lock" {
            parse_pipfile_lock(path)
        } else {
            parse_requirements_txt(path)
        }
    }
}

fn parse_requirements_txt(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let mut components = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments, empty lines, and options
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Format: package==version or package>=version
        // We only care about pinned versions (==)
        if let Some((name, version)) = line.split_once("==") {
            let name = name.trim();
            let version = version.trim().split(';').next().unwrap_or("").trim();
            if !name.is_empty() && !version.is_empty() {
                components.push(
                    Component::new(name, version, Ecosystem::PyPI)
                        .with_source(path.to_path_buf()),
                );
            }
        } else if let Some((name, version)) = line.split_once(">=") {
            // Also capture >= versions as minimum known version
            let name = name.trim();
            let version = version
                .trim()
                .split(',')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() && !version.is_empty() {
                components.push(
                    Component::new(name, version, Ecosystem::PyPI)
                        .with_source(path.to_path_buf()),
                );
            }
        }
    }

    Ok(components)
}

fn parse_pipfile_lock(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("json parse: {e}"))?;

    let mut components = Vec::new();

    // Pipfile.lock has "default" and "develop" sections
    for section in ["default", "develop"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (name, val) in deps {
                let version = val
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim_start_matches("==")
                    .to_string();
                if !version.is_empty() {
                    components.push(
                        Component::new(name, &version, Ecosystem::PyPI)
                            .with_source(path.to_path_buf()),
                    );
                }
            }
        }
    }

    Ok(components)
}
