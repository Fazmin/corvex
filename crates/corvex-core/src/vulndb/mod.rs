//! Vulnerability database engine.
//!
//! Provides a local SQLite-backed CVE database with support for multiple
//! data sources (NVD, OSV, EPSS), CPE matching, and offline operation.

pub mod cpe;
pub mod epss;
pub mod export;
pub mod import;
pub mod models;
pub mod nvd;
pub mod osv;
pub mod schema;
pub mod update;

use crate::vulndb::cpe::{cpe_matches_target, version_in_range};
use crate::vulndb::models::{CveRecord, EpssScore, FixInfo};
use crate::vulndb::nvd::NvdCveItem;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing;

/// Embedded NVD+EPSS snapshot (gzip-compressed SQLite), built at compile time.
/// Empty if no snapshot was available during the build.
const VULNDB_SNAPSHOT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vulndb_snapshot.bin"));

/// Whether an embedded snapshot is available.
pub fn has_embedded_snapshot() -> bool {
    !VULNDB_SNAPSHOT.is_empty()
}

/// The main vulnerability database handle.
pub struct VulnDb {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl VulnDb {
    /// Open (or create) a vulnerability database at the given path.
    pub fn open(path: &Path) -> Result<Self, String> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| format!("failed to open vulndb at {}: {e}", path.display()))?;

        // Enable WAL mode for better concurrent access
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("PRAGMA failed: {e}"))?;

        schema::init_schema(&conn).map_err(|e| format!("schema init failed: {e}"))?;

        tracing::info!(target: "vulndb", "opened vulnerability database at {}", path.display());

        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// Open the default vulnerability database at `~/.corvex/vulndb.sqlite`.
    ///
    /// If no database file exists on disk and an embedded snapshot was compiled
    /// into the binary, the snapshot is extracted first. This makes the tool
    /// work out-of-the-box without any network download.
    pub fn open_default() -> Result<Self, String> {
        let path = default_db_path()?;

        // If no DB file on disk yet, try to seed from the embedded snapshot
        if !path.exists() && has_embedded_snapshot() {
            seed_from_snapshot(&path)?;
        }

        Self::open(&path)
    }

    /// Get a reference to the underlying connection (for export/import).
    pub(crate) fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }

    /// Get the database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Run VACUUM to reclaim space and compact the database file.
    /// Useful after incremental updates that upsert many rows.
    pub fn vacuum(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        // VACUUM cannot run in WAL mode transactions, so switch to DELETE journal first
        conn.execute_batch("PRAGMA journal_mode=DELETE; VACUUM; PRAGMA journal_mode=WAL;")
            .map_err(|e| format!("vacuum failed: {e}"))?;
        Ok(())
    }

    // ---- Metadata operations ----

    /// Get a metadata value by key.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM db_meta WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("get_meta failed: {e}"))
    }

    /// Set a metadata value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO db_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )
        .map_err(|e| format!("set_meta failed: {e}"))?;
        Ok(())
    }

    /// Check if the database is stale (last update > max_age_secs ago).
    pub fn is_stale(&self, max_age_secs: u64) -> Result<bool, String> {
        match self.get_meta("last_nvd_update")? {
            None => Ok(true),
            Some(ts) => {
                // Parse ISO 8601 timestamp
                let fmt = time::format_description::well_known::Iso8601::DEFAULT;
                let last = time::OffsetDateTime::parse(&ts, &fmt)
                    .map_err(|e| format!("parse timestamp failed: {e}"))?;
                let now = time::OffsetDateTime::now_utc();
                let age = (now - last).whole_seconds() as u64;
                Ok(age > max_age_secs)
            }
        }
    }

    /// Clear all data (for full refresh).
    pub fn clear_all(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "DELETE FROM epss_scores;
             DELETE FROM cve_references;
             DELETE FROM cpe_matches;
             DELETE FROM fixes;
             DELETE FROM cves;
             DELETE FROM db_meta WHERE key != 'schema_version';",
        )
        .map_err(|e| format!("clear_all failed: {e}"))?;
        Ok(())
    }

    // ---- Batch insert operations (used by update) ----

    /// Upsert a batch of NVD CVE items into the database.
    pub fn upsert_nvd_batch(&self, items: &[NvdCveItem]) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("tx start failed: {e}"))?;

        for item in items {
            let record = item.to_cve_record();
            tx.execute(
                "INSERT OR REPLACE INTO cves (cve_id, description, published, modified, cvss_v31_score, cvss_v31_vector, severity, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    record.cve_id,
                    record.description,
                    record.published,
                    record.modified,
                    record.cvss_v31_score,
                    record.cvss_v31_vector,
                    record.severity,
                    record.source,
                ],
            ).map_err(|e| format!("upsert cve failed: {e}"))?;

            // Delete old CPE matches and references for this CVE
            tx.execute("DELETE FROM cpe_matches WHERE cve_id = ?1", [&record.cve_id])
                .map_err(|e| format!("delete cpe failed: {e}"))?;
            tx.execute("DELETE FROM cve_references WHERE cve_id = ?1", [&record.cve_id])
                .map_err(|e| format!("delete refs failed: {e}"))?;

            for m in item.to_cpe_matches() {
                tx.execute(
                    "INSERT INTO cpe_matches (cve_id, cpe23_uri, vulnerable, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        m.cve_id,
                        m.cpe23_uri,
                        m.vulnerable as i32,
                        m.version_start_including,
                        m.version_start_excluding,
                        m.version_end_including,
                        m.version_end_excluding,
                    ],
                ).map_err(|e| format!("insert cpe failed: {e}"))?;
            }

            for r in item.to_references() {
                tx.execute(
                    "INSERT INTO cve_references (cve_id, url, source, tags) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![r.cve_id, r.url, r.source, r.tags.join(",")],
                ).map_err(|e| format!("insert ref failed: {e}"))?;
            }
        }

        tx.commit().map_err(|e| format!("commit failed: {e}"))?;
        Ok(())
    }

    /// Upsert a batch of EPSS scores.
    pub fn upsert_epss_batch(&self, scores: &[EpssScore]) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("tx start failed: {e}"))?;

        for s in scores {
            tx.execute(
                "INSERT OR REPLACE INTO epss_scores (cve_id, score, percentile, date) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![s.cve_id, s.score, s.percentile, s.date],
            ).map_err(|e| format!("upsert epss failed: {e}"))?;
        }

        tx.commit().map_err(|e| format!("commit failed: {e}"))?;
        Ok(())
    }

    /// Insert fix information.
    pub fn insert_fixes(&self, fixes: &[FixInfo]) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("tx start failed: {e}"))?;

        for f in fixes {
            tx.execute(
                "INSERT INTO fixes (cve_id, ecosystem, package, fixed_version) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![f.cve_id, f.ecosystem, f.package, f.fixed_version],
            ).map_err(|e| format!("insert fix failed: {e}"))?;
        }

        tx.commit().map_err(|e| format!("commit failed: {e}"))?;
        Ok(())
    }

    // ---- Query operations ----

    /// Look up a single CVE by ID.
    pub fn get_cve(&self, cve_id: &str) -> Result<Option<CveRecord>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cve_id, description, published, modified, cvss_v31_score, cvss_v31_vector, severity, source
             FROM cves WHERE cve_id = ?1",
            [cve_id],
            |row| {
                Ok(CveRecord {
                    cve_id: row.get(0)?,
                    description: row.get(1)?,
                    published: row.get(2)?,
                    modified: row.get(3)?,
                    cvss_v31_score: row.get(4)?,
                    cvss_v31_vector: row.get(5)?,
                    severity: row.get(6)?,
                    source: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("get_cve failed: {e}"))
    }

    /// Look up the EPSS score for a CVE.
    pub fn get_epss(&self, cve_id: &str) -> Result<Option<EpssScore>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cve_id, score, percentile, date FROM epss_scores WHERE cve_id = ?1",
            [cve_id],
            |row| {
                Ok(EpssScore {
                    cve_id: row.get(0)?,
                    score: row.get(1)?,
                    percentile: row.get(2)?,
                    date: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("get_epss failed: {e}"))
    }

    /// Look up fixes for a CVE.
    pub fn get_fixes(&self, cve_id: &str) -> Result<Vec<FixInfo>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT cve_id, ecosystem, package, fixed_version FROM fixes WHERE cve_id = ?1")
            .map_err(|e| format!("prepare failed: {e}"))?;
        let fixes = stmt
            .query_map([cve_id], |row| {
                Ok(FixInfo {
                    cve_id: row.get(0)?,
                    ecosystem: row.get(1)?,
                    package: row.get(2)?,
                    fixed_version: row.get(3)?,
                })
            })
            .map_err(|e| format!("query failed: {e}"))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(fixes)
    }

    /// Find all CVEs affecting a specific vendor:product:version combination.
    /// Collects matching CVE IDs first, then fetches full records.
    pub fn lookup_component(
        &self,
        vendor: &str,
        product: &str,
        version: &str,
    ) -> Result<Vec<(CveRecord, Option<EpssScore>)>, String> {
        let matching_cve_ids = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT cve_id, cpe23_uri, version_start_including, version_start_excluding,
                            version_end_including, version_end_excluding
                     FROM cpe_matches WHERE vulnerable = 1",
                )
                .map_err(|e| format!("prepare failed: {e}"))?;

            let mut ids = Vec::new();
            let mut seen = std::collections::HashSet::new();

            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                })
                .map_err(|e| format!("query failed: {e}"))?;

            for row in rows {
                let (cve_id, cpe_uri, vsi, vse, vei, vee) = row.map_err(|e| format!("row: {e}"))?;
                if !cpe_matches_target(&cpe_uri, vendor, product) {
                    continue;
                }

                let version_match = if vsi.is_none() && vse.is_none() && vei.is_none() && vee.is_none() {
                    if let Some(cpe_parsed) = cpe::Cpe::parse(&cpe_uri) {
                        cpe_parsed.version == "*" || cpe_parsed.version == version
                    } else {
                        false
                    }
                } else {
                    version_in_range(
                        version,
                        vsi.as_deref(),
                        vse.as_deref(),
                        vei.as_deref(),
                        vee.as_deref(),
                    )
                };

                if version_match && seen.insert(cve_id.clone()) {
                    ids.push(cve_id);
                }
            }
            ids
        };

        // Now fetch full records for each matching CVE
        let mut results = Vec::new();
        for cve_id in &matching_cve_ids {
            if let Some(cve) = self.get_cve(cve_id)? {
                let epss = self.get_epss(cve_id).ok().flatten();
                results.push((cve, epss));
            }
        }
        Ok(results)
    }

    /// Get total number of CVEs in the database.
    pub fn cve_count(&self) -> Result<u64, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM cves", [], |row| row.get::<_, i64>(0))
            .map(|c| c as u64)
            .map_err(|e| format!("count failed: {e}"))
    }

    /// Get a summary of the database contents.
    pub fn summary(&self) -> Result<DbSummary, String> {
        let conn = self.conn.lock().unwrap();
        let cve_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cves", [], |r| r.get(0))
            .map_err(|e| format!("count cves: {e}"))?;
        let cpe_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cpe_matches", [], |r| r.get(0))
            .map_err(|e| format!("count cpe: {e}"))?;
        let epss_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM epss_scores", [], |r| r.get(0))
            .map_err(|e| format!("count epss: {e}"))?;
        let fix_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM fixes", [], |r| r.get(0))
            .map_err(|e| format!("count fixes: {e}"))?;

        drop(conn);
        let last_nvd = self.get_meta("last_nvd_update")?.unwrap_or_default();
        let last_epss = self.get_meta("last_epss_update")?.unwrap_or_default();

        Ok(DbSummary {
            cve_count: cve_count as u64,
            cpe_match_count: cpe_count as u64,
            epss_count: epss_count as u64,
            fix_count: fix_count as u64,
            last_nvd_update: last_nvd,
            last_epss_update: last_epss,
        })
    }
}

/// Summary of database contents.
#[derive(Debug, Clone)]
pub struct DbSummary {
    pub cve_count: u64,
    pub cpe_match_count: u64,
    pub epss_count: u64,
    pub fix_count: u64,
    pub last_nvd_update: String,
    pub last_epss_update: String,
}

/// Get the default database path.
pub fn default_db_path() -> Result<PathBuf, String> {
    let home = if cfg!(windows) {
        std::env::var("APPDATA").unwrap_or_else(|_| {
            std::env::var("USERPROFILE").unwrap_or_else(|_| ".".to_string())
        })
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
    };
    let base = PathBuf::from(home);
    let dir = if cfg!(windows) {
        base.join("corvex")
    } else {
        base.join(".corvex")
    };
    Ok(dir.join("vulndb.sqlite"))
}

/// Extract the embedded NVD+EPSS snapshot to a file on disk.
/// The snapshot is gzip-compressed SQLite embedded at compile time.
fn seed_from_snapshot(path: &Path) -> Result<(), String> {
    use std::io::Read;

    tracing::info!(
        target: "vulndb",
        "seeding vulnerability database from embedded snapshot ({} bytes compressed)",
        VULNDB_SNAPSHOT.len()
    );

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir: {e}"))?;
    }

    // Decompress gzip → raw SQLite
    let mut decoder = flate2::read::GzDecoder::new(VULNDB_SNAPSHOT);
    let mut raw = Vec::new();
    decoder
        .read_to_end(&mut raw)
        .map_err(|e| format!("decompress snapshot: {e}"))?;

    std::fs::write(path, &raw)
        .map_err(|e| format!("write snapshot to {}: {e}", path.display()))?;

    tracing::info!(
        target: "vulndb",
        "extracted snapshot ({} bytes) to {}",
        raw.len(),
        path.display()
    );

    Ok(())
}

/// rusqlite optional helper
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
