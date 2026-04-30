//! corvex-desktop build script.
//!
//! Three responsibilities:
//!   1. The Tauri framework's standard `tauri_build::build()` step (icons,
//!      Windows resource manifests, etc).
//!   2. Resolve the on-disk `rules.sqlite` path that `src/rules_embed.rs`
//!      will `include_bytes!` into the binary.
//!   3. Same trick for `devices.sqlite` (the SNMP device-signature
//!      catalog produced by `corvex-devicedb-builder`), wired up by
//!      `src/device_embed.rs`.
//!
//! For both catalogs, if the canonical path is missing on a fresh
//! clone we emit a zero-byte placeholder and the runtime falls back
//! to the cwd / exe-dir lookup chain instead. That keeps developer
//! builds compiling even before someone has run the builder once.

use std::path::{Path, PathBuf};

fn main() {
    tauri_build::build();

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    // crates/corvex-desktop -> ../..
    let repo_root = manifest_dir.join("..").join("..");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set"));

    embed_sqlite(
        &repo_root
            .join("program")
            .join("rules")
            .join("rules.sqlite"),
        &out_dir,
        "rules.sqlite",
        "CORVEX_RULES_SQLITE_PATH",
        "run `.\\scripts\\build-rules-snapshot.ps1` (or \
         `cargo run -p corvex-rules-builder -- --sources rules-sources --output program/rules/rules.sqlite`)",
    );
    embed_sqlite(
        &repo_root
            .join("program")
            .join("devicedb")
            .join("devices.sqlite"),
        &out_dir,
        "devices.sqlite",
        "CORVEX_DEVICES_SQLITE_PATH",
        "run `cargo run -p corvex-devicedb-builder` (defaults pick the right paths)",
    );
}

/// Resolve `canonical` and stamp its path into `env_var` so
/// `include_bytes!(env!(...))` picks up the right file. Falls back
/// to a zero-byte placeholder under `OUT_DIR` if the catalog hasn't
/// been built yet.
fn embed_sqlite(
    canonical: &Path,
    out_dir: &Path,
    label: &str,
    env_var: &str,
    rebuild_hint: &str,
) {
    println!("cargo:rerun-if-changed={}", canonical.display());

    if canonical.exists() {
        let bytes = std::fs::metadata(canonical)
            .map(|m| m.len())
            .unwrap_or(0);
        println!(
            "cargo:warning=corvex-desktop: embedding {label} ({} bytes) from {}",
            bytes,
            canonical.display()
        );
        println!("cargo:rustc-env={env_var}={}", canonical.display());
    } else {
        let placeholder = out_dir.join(format!("{label}.placeholder"));
        std::fs::write(&placeholder, b"").expect("write placeholder");
        println!(
            "cargo:warning=corvex-desktop: no {label} at {} - embedding empty placeholder; \
             {rebuild_hint} then rebuild to embed the real catalog",
            canonical.display()
        );
        println!("cargo:rustc-env={env_var}={}", placeholder.display());
    }
}
