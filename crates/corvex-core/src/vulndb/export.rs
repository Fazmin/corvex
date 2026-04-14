//! JSON export for the vulnerability database.

use crate::vulndb::models::{CpeMatch, CveFullRecord, CveRecord, CveReference, EpssScore};
use crate::vulndb::VulnDb;
use std::fs;
use std::path::Path;
use tracing;

/// Export the entire vulnerability database to a JSON file.
pub fn export_json(db: &VulnDb, path: &Path) -> Result<u64, String> {
    tracing::info!(target: "vulndb", "exporting to {}", path.display());

    let conn = db.conn();

    // Fetch all CVEs
    let mut stmt = conn
        .prepare(
            "SELECT cve_id, description, published, modified, cvss_v31_score, cvss_v31_vector, severity, source
             FROM cves ORDER BY cve_id",
        )
        .map_err(|e| format!("query cves failed: {e}"))?;

    let cves: Vec<CveRecord> = stmt
        .query_map([], |row| {
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
        })
        .map_err(|e| format!("query failed: {e}"))?
        .filter_map(|r| r.ok())
        .collect();

    let count = cves.len() as u64;
    let mut records = Vec::with_capacity(cves.len());

    for cve in cves {
        // Fetch CPE matches
        let mut cpe_stmt = conn
            .prepare(
                "SELECT cve_id, cpe23_uri, vulnerable, version_start_including, version_start_excluding, version_end_including, version_end_excluding
                 FROM cpe_matches WHERE cve_id = ?1",
            )
            .map_err(|e| format!("prepare cpe query failed: {e}"))?;

        let cpe_matches: Vec<CpeMatch> = cpe_stmt
            .query_map([&cve.cve_id], |row| {
                Ok(CpeMatch {
                    cve_id: row.get(0)?,
                    cpe23_uri: row.get(1)?,
                    vulnerable: row.get::<_, i32>(2)? != 0,
                    version_start_including: row.get(3)?,
                    version_start_excluding: row.get(4)?,
                    version_end_including: row.get(5)?,
                    version_end_excluding: row.get(6)?,
                })
            })
            .map_err(|e| format!("cpe query failed: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

        // Fetch references
        let mut ref_stmt = conn
            .prepare("SELECT cve_id, url, source, tags FROM cve_references WHERE cve_id = ?1")
            .map_err(|e| format!("prepare ref query failed: {e}"))?;

        let references: Vec<CveReference> = ref_stmt
            .query_map([&cve.cve_id], |row| {
                let tags_str: String = row.get(3)?;
                Ok(CveReference {
                    cve_id: row.get(0)?,
                    url: row.get(1)?,
                    source: row.get(2)?,
                    tags: tags_str
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect(),
                })
            })
            .map_err(|e| format!("ref query failed: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

        // Fetch EPSS
        let epss: Option<EpssScore> = conn
            .query_row(
                "SELECT cve_id, score, percentile, date FROM epss_scores WHERE cve_id = ?1",
                [&cve.cve_id],
                |row| {
                    Ok(EpssScore {
                        cve_id: row.get(0)?,
                        score: row.get(1)?,
                        percentile: row.get(2)?,
                        date: row.get(3)?,
                    })
                },
            )
            .ok();

        records.push(CveFullRecord {
            cve: cve,
            cpe_matches,
            references,
            epss,
        });
    }

    let json = serde_json::to_string_pretty(&records)
        .map_err(|e| format!("JSON serialize failed: {e}"))?;

    fs::write(path, json).map_err(|e| format!("write failed: {e}"))?;

    tracing::info!(target: "vulndb", "exported {} CVE records", count);
    Ok(count)
}
