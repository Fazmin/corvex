//! End-to-end smoke test: load the bundled template directory and
//! confirm at least one template is classified as Supported.

use corvex_nuclei::parser::{load_file, LoadOutcome, SkipReason};
use corvex_nuclei::TemplateStore;
use std::path::PathBuf;
use walkdir::WalkDir;

fn repo_root() -> PathBuf {
    // Workspace layout: this test file lives at
    // crates/corvex-nuclei/tests/bundle_smoke.rs
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn loads_bundled_nuclei_directory() {
    let root = repo_root().join("program").join("databases").join("nuclei");
    assert!(
        root.exists(),
        "expected bundled nuclei dir at {}",
        root.display()
    );

    let mut store = TemplateStore::new();
    store.load_dir(&root).expect("load bundled nuclei dir");

    let counts = store.counts();
    eprintln!(
        "nuclei bundle: {} supported, {} skipped",
        counts.supported, counts.skipped
    );
    for (bucket, n) in &counts.by_bucket {
        eprintln!("  skipped[{bucket}] = {n}");
    }
    assert!(
        counts.supported >= 1,
        "expected at least one supported template; got {:?}",
        counts
    );

    // `parse_error` skips signal a schema bug in the engine, not a
    // legitimate feature gap. DSL / interactsh / unsupported-feature
    // buckets are expected once the real upstream bundle is extracted.
    for (bucket, count) in &counts.by_bucket {
        if bucket == "parse_error" {
            // Gather detail so the failure message is actionable.
            let mut samples = Vec::new();
            for entry in WalkDir::new(&root).into_iter().filter_map(|e| e.ok()) {
                if !entry.file_type().is_file() {
                    continue;
                }
                let ext = entry
                    .path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if !matches!(ext, "yaml" | "yml") {
                    continue;
                }
                if let Ok(LoadOutcome::Skipped {
                    reason: SkipReason::ParseError(msg),
                    ..
                }) = load_file(entry.path())
                {
                    samples.push(format!(
                        "{}: {}",
                        entry
                            .path()
                            .strip_prefix(&root)
                            .unwrap_or(entry.path())
                            .display(),
                        msg.lines().next().unwrap_or("").chars().take(160).collect::<String>()
                    ));
                    if samples.len() >= 5 {
                        break;
                    }
                }
            }
            panic!(
                "bundle produced {count} parse_error skips. First few:\n  - {}",
                samples.join("\n  - ")
            );
        }
    }
}
