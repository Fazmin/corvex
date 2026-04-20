//! End-to-end smoke test: load the bundled template directory and
//! confirm at least one template is classified as Supported.

use corvex_nuclei::TemplateStore;
use std::path::PathBuf;

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
    assert!(
        counts.supported >= 1,
        "expected at least one supported template; got {:?}",
        counts
    );
    // Every bundled template should classify as supported — parse or
    // skip buckets in the seed are bugs.
    assert_eq!(
        counts.skipped, 0,
        "bundled seed should not produce skipped entries; got {:?}",
        counts.by_bucket
    );
}
