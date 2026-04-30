//! Embedded copy of `devices.sqlite`, plus the extract-on-first-run
//! logic that turns it into a real file `corvex_devicedb` can open.
//!
//! Same shape as `rules_embed.rs`. We extract instead of opening
//! `:memory:` because the runtime catalog reader (`DeviceCatalog::open`)
//! takes a path — and keeping the on-disk-file path identical to the
//! dev workflow (`./devices.sqlite` next to the binary) means a power
//! user can swap catalogs between launches without rebuilding.

use std::path::{Path, PathBuf};

/// The embedded blob. `CORVEX_DEVICES_SQLITE_PATH` is stamped by
/// [`build.rs`](../../build.rs) and points at either the
/// repo-root `devices.sqlite` or an empty placeholder if the catalog
/// hadn't been built before this binary was.
pub const EMBEDDED_DEVICES_SQLITE: &[u8] =
    include_bytes!(env!("CORVEX_DEVICES_SQLITE_PATH"));

const SQLITE_HEADER: &[u8] = b"SQLite format 3\x00";
const APP_DATA_NAMESPACE: &str = "dev.fazminnizam.corvex-rust";
const FILENAME: &str = "devices.sqlite";

/// Quick check that the embedded blob is a real SQLite catalog
/// (non-empty + header bytes match). False for the build.rs
/// zero-byte placeholder.
pub fn embedded_is_real() -> bool {
    EMBEDDED_DEVICES_SQLITE.len() >= SQLITE_HEADER.len()
        && EMBEDDED_DEVICES_SQLITE.starts_with(SQLITE_HEADER)
}

/// Resolve the runtime path for the device catalog. Lookup order
/// mirrors `rules_embed::resolve_rules_path`:
///   1. `<cwd>/devices.sqlite` — power-user override, dev workflow.
///   2. `<exe-dir>/devices.sqlite` — sibling-of-binary install layout.
///   3. `<app_data_dir>/<namespace>/devices.sqlite` — extracted blob,
///      written on first launch (or whenever the on-disk content
///      drifts from the embedded bytes).
///   4. `None` — no catalog available; SNMP fingerprinting will be
///      effectively disabled and `DeviceCatalog::default()` fills in.
pub fn resolve_devices_path() -> Option<PathBuf> {
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join(FILENAME);
        if looks_like_sqlite(&p) {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(FILENAME);
            if looks_like_sqlite(&p) {
                return Some(p);
            }
        }
    }
    if embedded_is_real() {
        if let Some(extracted) = ensure_extracted() {
            return Some(extracted);
        }
    }
    None
}

fn looks_like_sqlite(p: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut head = [0u8; 16];
    matches!(f.read(&mut head), Ok(n) if n == head.len() && head == SQLITE_HEADER)
}

fn extracted_path() -> Option<PathBuf> {
    let base = dirs::data_local_dir()?;
    Some(base.join(APP_DATA_NAMESPACE).join(FILENAME))
}

fn ensure_extracted() -> Option<PathBuf> {
    let dst = extracted_path()?;
    if let Some(parent) = dst.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                target: "device_embed",
                "create app-data dir {}: {e}",
                parent.display()
            );
            return None;
        }
    }

    let needs_write = match std::fs::metadata(&dst) {
        Err(_) => true,
        Ok(meta) => {
            if (meta.len() as usize) != EMBEDDED_DEVICES_SQLITE.len() {
                true
            } else {
                use std::io::Read;
                match std::fs::File::open(&dst) {
                    Err(_) => true,
                    Ok(mut f) => {
                        let probe_len = EMBEDDED_DEVICES_SQLITE.len().min(4096);
                        let mut buf = vec![0u8; probe_len];
                        match f.read_exact(&mut buf) {
                            Err(_) => true,
                            Ok(()) => buf != EMBEDDED_DEVICES_SQLITE[..probe_len],
                        }
                    }
                }
            }
        }
    };

    if needs_write {
        if let Err(e) = std::fs::write(&dst, EMBEDDED_DEVICES_SQLITE) {
            tracing::warn!(target: "device_embed", "write {}: {e}", dst.display());
            return None;
        }
        tracing::info!(
            target: "device_embed",
            "extracted embedded devices.sqlite ({} bytes) to {}",
            EMBEDDED_DEVICES_SQLITE.len(),
            dst.display()
        );
    }
    Some(dst)
}
