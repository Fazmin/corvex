//! Manifest file parser trait and registry.

pub mod cargo_lock;
pub mod composer;
pub mod gemfile;
pub mod gomod;
pub mod maven;
pub mod npm;
pub mod python;

use crate::sca::component::Component;
use std::path::Path;

/// Trait for parsing dependency manifest files.
pub trait ManifestParser: Send + Sync {
    /// File names this parser can handle (e.g., "Cargo.lock").
    fn file_names(&self) -> &[&str];

    /// Check if this parser can handle the given path.
    fn can_parse(&self, path: &Path) -> bool {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            self.file_names().iter().any(|f| f.eq_ignore_ascii_case(name))
        } else {
            false
        }
    }

    /// Parse the file and extract components.
    fn parse(&self, path: &Path) -> Result<Vec<Component>, String>;
}

/// Get all registered parsers.
pub fn all_parsers() -> Vec<Box<dyn ManifestParser>> {
    vec![
        Box::new(cargo_lock::CargoLockParser),
        Box::new(npm::NpmParser),
        Box::new(python::PythonParser),
        Box::new(maven::MavenParser),
        Box::new(gomod::GoModParser),
        Box::new(gemfile::GemfileParser),
        Box::new(composer::ComposerParser),
    ]
}

/// Scan a directory for manifest files and extract all components.
pub fn scan_directory(dir: &Path) -> Result<Vec<Component>, String> {
    let parsers = all_parsers();
    let mut components = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        for parser in &parsers {
            if parser.can_parse(path) {
                match parser.parse(path) {
                    Ok(comps) => {
                        tracing::info!(
                            target: "sca",
                            "parsed {} components from {}",
                            comps.len(),
                            path.display()
                        );
                        components.extend(comps);
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "sca",
                            "failed to parse {}: {}",
                            path.display(),
                            e
                        );
                    }
                }
                break;
            }
        }
    }

    Ok(components)
}
