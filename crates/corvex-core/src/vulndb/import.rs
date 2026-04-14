//! JSON import for the vulnerability database.

use crate::vulndb::models::CveFullRecord;
use crate::vulndb::VulnDb;
use std::fs;
use std::path::Path;
use tracing;

/// Import vulnerability data from a JSON file into the database.
pub fn import_json(db: &VulnDb, path: &Path) -> Result<u64, String> {
    tracing::info!(target: "vulndb", "importing from {}", path.display());

    let data =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    let records: Vec<CveFullRecord> =
        serde_json::from_str(&data).map_err(|e| format!("JSON parse error: {e}"))?;

    let count = records.len() as u64;

    let conn = db.conn();
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("transaction start failed: {e}"))?;

    for record in &records {
        // Insert CVE
        tx.execute(
            "INSERT OR REPLACE INTO cves (cve_id, description, published, modified, cvss_v31_score, cvss_v31_vector, severity, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                record.cve.cve_id,
                record.cve.description,
                record.cve.published,
                record.cve.modified,
                record.cve.cvss_v31_score,
                record.cve.cvss_v31_vector,
                record.cve.severity,
                record.cve.source,
            ],
        ).map_err(|e| format!("insert cve failed: {e}"))?;

        // Insert CPE matches
        for m in &record.cpe_matches {
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
            ).map_err(|e| format!("insert cpe_match failed: {e}"))?;
        }

        // Insert references
        for r in &record.references {
            tx.execute(
                "INSERT INTO cve_references (cve_id, url, source, tags) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    r.cve_id,
                    r.url,
                    r.source,
                    r.tags.join(","),
                ],
            ).map_err(|e| format!("insert ref failed: {e}"))?;
        }

        // Insert EPSS if present
        if let Some(ref epss) = record.epss {
            tx.execute(
                "INSERT OR REPLACE INTO epss_scores (cve_id, score, percentile, date) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    epss.cve_id,
                    epss.score,
                    epss.percentile,
                    epss.date,
                ],
            ).map_err(|e| format!("insert epss failed: {e}"))?;
        }
    }

    tx.commit()
        .map_err(|e| format!("commit failed: {e}"))?;

    tracing::info!(target: "vulndb", "imported {} CVE records", count);
    Ok(count)
}
