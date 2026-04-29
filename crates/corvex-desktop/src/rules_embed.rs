//! Embedded copy of `rules.sqlite`, plus the extract-on-first-run logic
//! that turns it into a real file the rest of the codebase already knows
//! how to open.
//!
//! Why extract instead of opening a `:memory:` SQLite from the bytes? The
//! desktop's `rules_summary` Tauri command and the `corvex_rules::RuleStore`
//! reader both call `Connection::open_with_flags(path, READ_ONLY)`. Doing
//! the open over a real file keeps that code path identical to the dev
//! workflow where the user sits the catalog in cwd or exe-dir. The cost is
//! one ~7 MB write to `<app_data_dir>/rules.sqlite` on first launch (or
//! whenever the embedded blob's content changes) and zero per-scan
//! overhead.

use std::path::{Path, PathBuf};

/// The embedded blob. The `CORVEX_RULES_SQLITE_PATH` env var is stamped by
/// `build.rs` — it points at either the repo-root `rules.sqlite` or an
/// empty placeholder if the catalog wasn't built before the binary was.
pub const EMBEDDED_RULES_SQLITE: &[u8] = include_bytes!(env!("CORVEX_RULES_SQLITE_PATH"));

/// Magic-byte sniff: SQLite files always start with the literal
/// `b"SQLite format 3\0"`. Used to reject empty / placeholder embeds at
/// runtime so we don't write garbage to disk.
const SQLITE_HEADER: &[u8] = b"SQLite format 3\x00";

/// Quick check whether the embedded blob is a real SQLite catalog
/// (non-empty, header bytes match). False for the build.rs placeholder.
pub fn embedded_is_real() -> bool {
    EMBEDDED_RULES_SQLITE.len() >= SQLITE_HEADER.len()
        && EMBEDDED_RULES_SQLITE.starts_with(SQLITE_HEADER)
}

/// Resolve the runtime path the scanner should open. Lookup order:
///
///   1. `<cwd>/rules.sqlite` — power-user override; whatever sits next to
///      the working directory wins so a developer can swap catalogs
///      between scans without rebuilding.
///   2. `<exe-dir>/rules.sqlite` — sibling-of-binary install layout; this
///      is what `cp rules.sqlite target/debug/rules.sqlite` puts in place.
///   3. `<app_data_dir>/corvex/rules.sqlite` — the extracted copy of the
///      embedded blob. Written on first launch (or whenever the on-disk
///      content's length / first 4 KB don't match the embedded bytes,
///      which catches the "user upgraded the binary" case).
///   4. `None` — no catalog available; binary falls back to legacy-only
///      behaviour with a debug log.
///
/// Returns `Some(path)` only when the chosen file passes a basic header
/// sniff so callers don't try to open obviously-malformed catalogs.
pub fn resolve_rules_path() -> Option<PathBuf> {
    // 1. cwd
    if let Ok(cwd) = std::env::current_dir() {
        let p = cwd.join("rules.sqlite");
        if looks_like_sqlite(&p) {
            return Some(p);
        }
    }
    // 2. exe-dir
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("rules.sqlite");
            if looks_like_sqlite(&p) {
                return Some(p);
            }
        }
    }
    // 3. extracted blob in app_data_dir
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

/// Where the embedded blob is extracted to. `corvex/rules.sqlite` under
/// the platform's app-data directory mirrors the existing `history.sqlite`
/// / `exploitdb.sqlite` location pattern.
fn extracted_path() -> Option<PathBuf> {
    // Use the same convention as the rest of the desktop's on-disk state.
    // dirs::data_local_dir() resolves to %LOCALAPPDATA% on Windows,
    // ~/.local/share on Linux, ~/Library/Application Support on macOS.
    let base = dirs::data_local_dir()?;
    Some(base.join("dev.fazminnizam.corvex-rust").join("rules.sqlite"))
}

/// Write the embedded blob to disk if the destination is missing or
/// out-of-sync (length differs, or the first 4 KB don't match — a cheap
/// proxy for "binary was upgraded with a new catalog"). Returns the path
/// the bytes now live at, or None if extraction failed.
fn ensure_extracted() -> Option<PathBuf> {
    let dst = extracted_path()?;
    if let Some(parent) = dst.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                target: "rules_embed",
                "create app-data dir {}: {e}",
                parent.display()
            );
            return None;
        }
    }

    let needs_write = match std::fs::metadata(&dst) {
        Err(_) => true,
        Ok(meta) => {
            if (meta.len() as usize) != EMBEDDED_RULES_SQLITE.len() {
                true
            } else {
                // Header / first 4 KB check. Reading the whole file just to
                // compare would defeat the embed's startup-cost story.
                use std::io::Read;
                match std::fs::File::open(&dst) {
                    Err(_) => true,
                    Ok(mut f) => {
                        let probe_len = EMBEDDED_RULES_SQLITE.len().min(4096);
                        let mut buf = vec![0u8; probe_len];
                        match f.read_exact(&mut buf) {
                            Err(_) => true,
                            Ok(()) => buf != EMBEDDED_RULES_SQLITE[..probe_len],
                        }
                    }
                }
            }
        }
    };

    if needs_write {
        if let Err(e) = std::fs::write(&dst, EMBEDDED_RULES_SQLITE) {
            tracing::warn!(
                target: "rules_embed",
                "write {}: {e}",
                dst.display()
            );
            return None;
        }
        tracing::info!(
            target: "rules_embed",
            "extracted embedded rules.sqlite ({} bytes) to {}",
            EMBEDDED_RULES_SQLITE.len(),
            dst.display()
        );
    }
    Some(dst)
}
