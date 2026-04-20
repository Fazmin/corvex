//! Resolve filesystem locations where the Tier-1 bundled templates may
//! live. Callers (plugin + desktop UI) share this so they don't drift.

use std::path::PathBuf;

/// Candidate filesystem locations for the bundled Tier-1 templates.
/// Existing dirs only, in priority order.
///
/// Covered layouts:
///   - Source-tree run: `<cwd>/program/databases/nuclei/`
///   - Tauri Windows / Linux resource layout: `<exe_dir>/resources/program/databases/nuclei/`
///   - Tauri macOS .app: `<exe_dir>/../Resources/program/databases/nuclei/`
///   - Raw copy next to the binary: `<exe_dir>/program/databases/nuclei/`
pub fn default_roots() -> Vec<PathBuf> {
    let rel = PathBuf::from("program").join("databases").join("nuclei");
    let mut roots = Vec::new();

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    roots.push(cwd.join(&rel));
    roots.push(PathBuf::from(&rel));

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            roots.push(parent.join("resources").join(&rel));
            roots.push(parent.join("..").join("Resources").join(&rel));
            roots.push(parent.join(&rel));
            roots.push(parent.join("databases").join("nuclei"));
        }
    }

    roots.retain(|p| p.exists());
    roots
}

/// Tier-2 extras cache populated by the "Expand coverage" workflow.
pub fn extras_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(data) = user_data_dir() {
        roots.push(data.join("corvex").join("nuclei-templates"));
    }
    roots.retain(|p| p.exists());
    roots
}

fn user_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join(".local").join("share"))
            })
    }
}
