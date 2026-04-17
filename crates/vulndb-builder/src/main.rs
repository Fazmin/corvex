//! vulndb-builder — standalone tool to download NVD + EPSS data and produce
//! a compressed SQLite snapshot for embedding into the corvex binary.
//!
//! Usage:
//!   vulndb-builder                          # incremental if snapshot exists, full otherwise
//!   vulndb-builder --full                   # force full rebuild
//!   vulndb-builder --output path/out.db.gz  # custom output path
//!   vulndb-builder --api-key YOUR_KEY       # use NVD API key (faster)
//!
//! The resulting .db.gz file is picked up automatically by corvex-core's
//! build.rs at compile time and embedded into the final binary.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use corvex_core::vulndb::epss::EpssClient;
use corvex_core::vulndb::nvd::NvdClient;
use corvex_core::vulndb::VulnDb;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let api_key = arg_value(&args, "--api-key")
        .or_else(|| std::env::var("NVD_API_KEY").ok());
    let output = arg_value(&args, "--output")
        .map(PathBuf::from)
        .unwrap_or_else(default_output_path);
    let force_full = args.iter().any(|a| a == "--full");

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("vulndb-builder — download NVD + EPSS data into a compressed snapshot");
        println!();
        println!("Usage:");
        println!("  vulndb-builder [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --output <PATH>    Output file (default: program/vulndb/snapshot.db.gz)");
        println!("  --api-key <KEY>    NVD API key (or set NVD_API_KEY env var)");
        println!("                     Without key: 10 req/min. With key: 100 req/min.");
        println!("  --full             Force full rebuild (ignore existing snapshot)");
        println!("  --help             Show this help");
        println!();
        println!("Behavior:");
        println!("  If an existing snapshot is found at the output path, only CVEs");
        println!("  modified since the snapshot's last update are fetched. Use --full");
        println!("  to force a complete re-download.");
        println!();
        println!("The output .db.gz file is embedded into the corvex binary at compile time.");
        println!("Place it at program/vulndb/snapshot.db.gz and run: cargo build --release");
        return;
    }

    println!("========================================");
    println!("  Corvex Vulnerability Database Builder");
    println!("========================================");
    println!();
    println!("Output:  {}", output.display());
    println!("API key: {}", if api_key.is_some() { "provided (100 req/min)" } else { "none (10 req/min — set NVD_API_KEY for faster downloads)" });
    println!();

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    if let Err(e) = rt.block_on(run(output, api_key, force_full)) {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

async fn run(output: PathBuf, api_key: Option<String>, force_full: bool) -> Result<(), String> {
    let start = Instant::now();

    // Work with a temporary uncompressed DB file
    let raw_db_path = output.with_extension("db.tmp");

    // Ensure parent directory exists
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create directory: {e}"))?;
    }

    // Remove existing temp file if present
    let _ = std::fs::remove_file(&raw_db_path);

    // ---- Determine mode: incremental or full ----
    let existing_snapshot = output.exists() && !force_full;
    let mode_label;
    let since_timestamp: Option<String>;

    if existing_snapshot {
        println!("[1/4] Found existing snapshot — extracting for incremental update...");
        extract_gz(&output, &raw_db_path)?;

        // Open it to read the last update timestamp
        let tmp_db = VulnDb::open(&raw_db_path)?;
        since_timestamp = tmp_db.get_meta("last_nvd_update")?;
        drop(tmp_db);

        match &since_timestamp {
            Some(ts) => {
                println!("      Last NVD update: {}", ts);
                mode_label = "incremental";
            }
            None => {
                println!("      WARNING: existing snapshot has no timestamp, doing full rebuild");
                mode_label = "full (no prior timestamp)";
                // Wipe and start over
                std::fs::remove_file(&raw_db_path).ok();
            }
        }
    } else {
        if force_full {
            println!("[1/4] --full flag set — building from scratch...");
        } else {
            println!("[1/4] No existing snapshot found — building from scratch...");
        }
        since_timestamp = None;
        mode_label = "full";
    }

    // Open (or re-open) the DB
    let db = VulnDb::open(&raw_db_path)?;

    // ---- Download NVD data ----
    println!("[2/4] Downloading NVD CVE data ({} mode)...", mode_label);
    if since_timestamp.is_some() {
        println!("      Only fetching CVEs modified since last update.");
    } else {
        println!("      Without API key: ~30 min. With API key: ~5 min.");
    }
    println!("      Retries automatically on rate limits or transient errors.");
    println!();

    let nvd = NvdClient::new(api_key);
    let batch_count = std::sync::atomic::AtomicU64::new(0);
    let cve_count = std::sync::atomic::AtomicU64::new(0);

    let nvd_count = match &since_timestamp {
        Some(ts) => {
            nvd.fetch_modified(ts, |batch| {
                let n = batch_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let total = cve_count.fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed)
                    + batch.len() as u64;
                db.upsert_nvd_batch(&batch)?;
                eprint!("\r      Page {} — {} modified CVEs applied", n, total);
                Ok(())
            })
            .await?
        }
        None => {
            nvd.fetch_all(|batch| {
                let n = batch_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let total = cve_count.fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed)
                    + batch.len() as u64;
                db.upsert_nvd_batch(&batch)?;
                eprint!("\r      Page {} — {} CVEs inserted so far", n, total);
                Ok(())
            })
            .await?
        }
    };

    eprintln!();
    if since_timestamp.is_some() {
        println!("      Updated {} CVEs from NVD (incremental).", nvd_count);
    } else {
        println!("      Downloaded {} CVEs from NVD.", nvd_count);
    }

    // Set timestamp so next incremental update picks up from here
    let now = time::OffsetDateTime::now_utc();
    let now_str = now
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default();
    db.set_meta("last_nvd_update", &now_str)?;
    db.set_meta("snapshot_built", &now_str)?;

    // ---- Download EPSS data (always full — it's just ~30MB) ----
    println!("[3/4] Downloading EPSS exploit probability scores...");

    let epss = EpssClient::new();
    match epss.fetch_scores().await {
        Ok(scores) => {
            let count = scores.len();
            db.upsert_epss_batch(&scores)?;
            db.set_meta("last_epss_update", &now_str)?;
            println!("      Loaded {} EPSS scores.", count);
        }
        Err(e) => {
            println!("      WARNING: EPSS download failed (non-fatal): {e}");
        }
    }

    // Print summary
    let summary = db.summary()?;
    println!();
    println!("  Database summary:");
    println!("    CVEs:        {}", summary.cve_count);
    println!("    CPE matches: {}", summary.cpe_match_count);
    println!("    EPSS scores: {}", summary.epss_count);

    // VACUUM to reclaim space (important after incremental updates)
    let _ = db.vacuum();

    // Close the database before compressing
    drop(db);

    // ---- Compress to gzip ----
    println!();
    println!("[4/4] Compressing snapshot...");

    let raw_bytes = std::fs::read(&raw_db_path)
        .map_err(|e| format!("read temp db: {e}"))?;
    let raw_size = raw_bytes.len();

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(&raw_bytes)
        .map_err(|e| format!("gzip compress: {e}"))?;
    let compressed = encoder
        .finish()
        .map_err(|e| format!("gzip finish: {e}"))?;
    let gz_size = compressed.len();

    std::fs::write(&output, &compressed)
        .map_err(|e| format!("write {}: {e}", output.display()))?;

    // Clean up temp files
    let _ = std::fs::remove_file(&raw_db_path);
    // Also remove WAL/SHM if present
    let _ = std::fs::remove_file(raw_db_path.with_extension("db.tmp-wal"));
    let _ = std::fs::remove_file(raw_db_path.with_extension("db.tmp-shm"));

    let elapsed = start.elapsed();
    let ratio = if raw_size > 0 {
        (gz_size as f64 / raw_size as f64) * 100.0
    } else {
        0.0
    };

    println!();
    println!("========================================");
    println!("  Snapshot built successfully!");
    println!("========================================");
    println!();
    println!("  Mode:            {}", mode_label);
    println!("  Raw size:        {} MB", raw_size / (1024 * 1024));
    println!("  Compressed size: {} MB ({:.1}%)", gz_size / (1024 * 1024), ratio);
    println!("  Output:          {}", output.display());
    println!("  Time:            {:.0}s", elapsed.as_secs_f64());
    println!();
    println!("Next steps:");
    println!("  1. The snapshot is at: {}", output.display());
    println!("  2. Rebuild corvex to embed it:");
    println!("       cargo build --release");
    println!();
    println!("  Run vulndb-builder again later for incremental updates.");

    Ok(())
}

/// Extract a .gz file to a raw .db file.
fn extract_gz(gz_path: &Path, db_path: &Path) -> Result<(), String> {
    let file = std::fs::File::open(gz_path)
        .map_err(|e| format!("open {}: {e}", gz_path.display()))?;
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut raw = Vec::new();
    decoder
        .read_to_end(&mut raw)
        .map_err(|e| format!("decompress {}: {e}", gz_path.display()))?;
    std::fs::write(db_path, &raw)
        .map_err(|e| format!("write {}: {e}", db_path.display()))?;
    Ok(())
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn default_output_path() -> PathBuf {
    // Try to find the project root by looking for Cargo.toml
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..5 {
        if dir.join("Cargo.toml").exists() && dir.join("program").exists() {
            return dir.join("program").join("vulndb").join("snapshot.db.gz");
        }
        if let Some(parent) = dir.parent() {
            dir = parent.to_path_buf();
        } else {
            break;
        }
    }
    // Fallback: current directory
    PathBuf::from("snapshot.db.gz")
}
