//! Maven pom.xml parser for Java dependencies.

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct MavenParser;

impl ManifestParser for MavenParser {
    fn file_names(&self) -> &[&str] {
        &["pom.xml"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

        let mut components = Vec::new();
        let mut in_dependency = false;
        let mut group_id = String::new();
        let mut artifact_id = String::new();
        let mut version = String::new();

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "<dependency>" || trimmed.starts_with("<dependency ") {
                in_dependency = true;
                group_id.clear();
                artifact_id.clear();
                version.clear();
            } else if trimmed == "</dependency>" {
                if in_dependency && !artifact_id.is_empty() && !version.is_empty() {
                    let name = if group_id.is_empty() {
                        artifact_id.clone()
                    } else {
                        format!("{}:{}", group_id, artifact_id)
                    };
                    let mut comp = Component::new(&name, &version, Ecosystem::Maven);
                    comp.vendor = if group_id.is_empty() {
                        None
                    } else {
                        Some(group_id.clone())
                    };
                    comp.source_file = Some(path.to_path_buf());
                    components.push(comp);
                }
                in_dependency = false;
            } else if in_dependency {
                if let Some(val) = extract_xml_value(trimmed, "groupId") {
                    group_id = val;
                } else if let Some(val) = extract_xml_value(trimmed, "artifactId") {
                    artifact_id = val;
                } else if let Some(val) = extract_xml_value(trimmed, "version") {
                    // Skip variable references like ${project.version}
                    if !val.starts_with("${") {
                        version = val;
                    }
                }
            }
        }

        Ok(components)
    }
}

/// Extract the text value from a simple XML element like `<tag>value</tag>`.
fn extract_xml_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    if let Some(start) = line.find(&open) {
        if let Some(end) = line.find(&close) {
            let val_start = start + open.len();
            if val_start < end {
                return Some(line[val_start..end].trim().to_string());
            }
        }
    }
    None
}
