//! Binary analysis engine.
//!
//! Scans binary files for known vulnerable library components by extracting
//! printable strings and matching against library-specific patterns.

pub mod archive;
pub mod checker;
pub mod checkers;
pub mod strings;
pub mod version;

use crate::binary::checker::DetectedLibrary;
use crate::sca::component::{Component, Ecosystem};
use crate::vulndb::cpe::Cpe;
use std::path::Path;
use tracing;

/// Scan a file or directory for vulnerable binary components.
pub fn scan_path(
    path: &Path,
    recursive: bool,
    extract_archives: bool,
) -> Result<Vec<Component>, String> {
    let checkers = checkers::register_all();
    let mut components = Vec::new();

    if path.is_file() {
        scan_file(path, &checkers, extract_archives, &mut components)?;
    } else if path.is_dir() {
        scan_directory(path, &checkers, recursive, extract_archives, &mut components)?;
    } else {
        return Err(format!("{} is not a file or directory", path.display()));
    }

    Ok(components)
}

fn scan_file(
    path: &Path,
    checkers: &[Box<dyn checker::BinaryChecker>],
    extract_archives: bool,
    components: &mut Vec<Component>,
) -> Result<(), String> {
    // Check if it's an archive
    if extract_archives {
        if let Some(archive_type) = archive::detect_archive_type(path) {
            tracing::info!(target: "binary", "extracting archive: {}", path.display());
            match archive::extract_archive(path, archive_type) {
                Ok(temp_dir) => {
                    scan_directory(&temp_dir, checkers, true, false, components)?;
                    archive::cleanup_temp_dir(&temp_dir);
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(target: "binary", "archive extraction failed: {}", e);
                    // Fall through to scan as a regular file
                }
            }
        }
    }

    // Extract strings from the binary
    let file_strings = strings::extract_strings(path)?;
    if file_strings.is_empty() {
        return Ok(());
    }

    // Run all checkers
    for ch in checkers {
        if let Some(detected) = ch.detect(&file_strings) {
            tracing::info!(
                target: "binary",
                "detected {} {} in {}",
                detected.name,
                detected.version,
                path.display()
            );
            components.push(detected_to_component(&detected, path));
        }
    }

    Ok(())
}

fn scan_directory(
    dir: &Path,
    checkers: &[Box<dyn checker::BinaryChecker>],
    recursive: bool,
    extract_archives: bool,
    components: &mut Vec<Component>,
) -> Result<(), String> {
    let walker = if recursive {
        walkdir::WalkDir::new(dir).max_depth(10)
    } else {
        walkdir::WalkDir::new(dir).max_depth(1)
    };

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Err(e) = scan_file(entry.path(), checkers, extract_archives, components) {
                tracing::warn!(
                    target: "binary",
                    "failed to scan {}: {}",
                    entry.path().display(),
                    e
                );
            }
        }
    }

    Ok(())
}

/// Convert a DetectedLibrary to a Component.
fn detected_to_component(lib: &DetectedLibrary, source: &Path) -> Component {
    let cpe = Cpe::build(&lib.cpe_vendor, &lib.cpe_product, &lib.version);
    let mut comp = Component::new(&lib.name, &lib.version, Ecosystem::Unknown);
    comp.cpe = Some(cpe);
    comp.vendor = Some(lib.cpe_vendor.clone());
    comp.source_file = Some(source.to_path_buf());
    comp
}
