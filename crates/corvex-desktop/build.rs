//! corvex-desktop build script.
//!
//! Two responsibilities:
//!   1. The Tauri framework's standard `tauri_build::build()` step (icons,
//!      Windows resource manifests, etc).
//!   2. Resolve the on-disk `rules.sqlite` path that `src/rules_embed.rs`
//!      will `include_bytes!` into the binary. If the canonical path
//!      (`<repo-root>/rules.sqlite`) is missing on a fresh clone, fall
//!      back to an empty placeholder so the build doesn't fail — the
//!      runtime detects the empty case and uses the cwd / exe-dir
//!      lookup chain instead.

use std::path::PathBuf;

fn main() {
    tauri_build::build();

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"));
    // crates/corvex-desktop -> ../..
    let repo_root = manifest_dir.join("..").join("..");
    let canonical = repo_root.join("rules.sqlite");

    println!("cargo:rerun-if-changed={}", canonical.display());

    if canonical.exists() {
        let bytes = std::fs::metadata(&canonical)
            .map(|m| m.len())
            .unwrap_or(0);
        println!(
            "cargo:warning=corvex-desktop: embedding rules.sqlite ({} bytes) from {}",
            bytes,
            canonical.display()
        );
        println!(
            "cargo:rustc-env=CORVEX_RULES_SQLITE_PATH={}",
            canonical.display()
        );
    } else {
        let out_dir =
            PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set"));
        let placeholder = out_dir.join("rules.sqlite.placeholder");
        std::fs::write(&placeholder, b"").expect("write placeholder");
        println!(
            "cargo:warning=corvex-desktop: no rules.sqlite at {} - embedding empty placeholder; \
             run `cargo run -p corvex-rules-builder -- --sources rules-sources --output rules.sqlite` \
             then rebuild to embed the real catalog",
            canonical.display()
        );
        println!(
            "cargo:rustc-env=CORVEX_RULES_SQLITE_PATH={}",
            placeholder.display()
        );
    }
}
