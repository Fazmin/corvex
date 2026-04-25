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

/// Directories the walker always skips. Traversing these on a
/// typical project would cost minutes and produce tens of thousands
/// of duplicate components (every installed package ships its own
/// `package.json`). An npm project's lockfile at the root already
/// captures the full transitive graph, so descending into
/// `node_modules/` adds no real signal and enormous cost.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    "target",        // Rust build output
    "dist",
    "build",
    "out",
    ".next",         // Next.js build cache
    ".nuxt",
    ".svelte-kit",
    ".cache",
    "vendor",        // Go / Composer / Ruby vendored deps
    "bower_components",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".gradle",
    ".idea",
    ".vscode",
];

fn is_skip_dir(name: &str) -> bool {
    SKIP_DIRS.iter().any(|s| s.eq_ignore_ascii_case(name))
}

/// Scan a directory for manifest files and extract all components.
///
/// Progress is reported through the optional callback — the desktop
/// wraps this to emit status into `GlobalState::stage` so the UI can
/// render "parsed 42 components from package-lock.json" instead of a
/// blank running indicator.
pub fn scan_directory(dir: &Path) -> Result<Vec<Component>, String> {
    scan_directory_with_progress(dir, |_| {})
}

pub fn scan_directory_with_progress<F>(
    dir: &Path,
    mut progress: F,
) -> Result<Vec<Component>, String>
where
    F: FnMut(&str),
{
    let parsers = all_parsers();
    let mut components = Vec::new();
    let mut files_scanned = 0u64;
    let mut manifests_parsed = 0u64;

    progress(&format!("scanning {}", dir.display()));

    let walker = walkdir::WalkDir::new(dir)
        .max_depth(6)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Keep files, keep the root dir, skip heavy build / vendor
            // trees. This is the single biggest determinant of scan
            // time on a real project — without it, node_modules alone
            // can push a dep scan past 10 minutes.
            if !e.file_type().is_dir() {
                return true;
            }
            if e.depth() == 0 {
                return true;
            }
            let name = e.file_name().to_string_lossy();
            !is_skip_dir(&name)
        });

    for entry in walker.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        files_scanned += 1;
        if files_scanned % 200 == 0 {
            progress(&format!(
                "walked {files_scanned} files, parsed {manifests_parsed} manifests"
            ));
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
                        manifests_parsed += 1;
                        let display_name = path
                            .strip_prefix(dir)
                            .unwrap_or(path)
                            .display()
                            .to_string();
                        progress(&format!(
                            "parsed {} components from {}",
                            comps.len(),
                            display_name
                        ));
                        components.extend(comps);
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "sca",
                            "failed to parse {}: {}",
                            path.display(),
                            e
                        );
                        progress(&format!("parse error on {}: {e}", path.display()));
                    }
                }
                break;
            }
        }
    }

    progress(&format!(
        "done walking — {files_scanned} files, {manifests_parsed} manifests, {} components",
        components.len()
    ));

    Ok(components)
}
