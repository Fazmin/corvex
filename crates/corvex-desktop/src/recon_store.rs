//! SQLite persistence for recon runs + findings.
//!
//! Opens its own connection to the same `history.sqlite` file the
//! rest of the app uses (WAL mode keeps this safe — the existing
//! HistoryDb and ProxyDb already share the file). Runs get one row
//! each; findings FK-cascade on run delete.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS recon_runs (
    id              TEXT PRIMARY KEY,
    domain          TEXT NOT NULL,
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    status          TEXT NOT NULL,
    passive_sources TEXT,
    active_enabled  INTEGER NOT NULL,
    wildcard_ips    TEXT,
    found_subdomains INTEGER NOT NULL DEFAULT 0,
    found_records    INTEGER NOT NULL DEFAULT 0,
    error           TEXT
);

CREATE TABLE IF NOT EXISTS recon_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    name         TEXT NOT NULL,
    value        TEXT,
    record_type  TEXT,
    sources      TEXT,
    discovered_at INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES recon_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_recon_findings_run ON recon_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_recon_runs_started ON recon_runs(started_at DESC);
"#;

/// Tagged kind for a single finding row. Same table stores
/// subdomains + records + zone-transfer evidence — `kind` keeps them
/// discriminated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconFindingKind {
    Subdomain,
    Record,
    ZoneTransfer,
}

impl ReconFindingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Subdomain => "subdomain",
            Self::Record => "record",
            Self::ZoneTransfer => "zone-transfer",
        }
    }
}

fn parse_finding_kind(s: &str) -> ReconFindingKind {
    match s {
        "record" => ReconFindingKind::Record,
        "zone-transfer" => ReconFindingKind::ZoneTransfer,
        _ => ReconFindingKind::Subdomain,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconRunSummary {
    pub id: String,
    pub domain: String,
    pub started_at_unix: i64,
    pub ended_at_unix: Option<i64>,
    pub status: String,
    pub passive_sources: Vec<String>,
    pub active_enabled: bool,
    pub wildcard_ips: Vec<String>,
    pub found_subdomains: u64,
    pub found_records: u64,
    pub error: Option<String>,
}

/// One pending finding handed to [`ReconDb::insert_findings_batch`].
/// Owns its strings so the caller can drop the originating event.
#[derive(Debug, Clone)]
pub struct PendingFinding {
    pub kind: ReconFindingKind,
    pub name: String,
    pub value: Option<String>,
    pub record_type: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconFindingRow {
    pub id: i64,
    pub run_id: String,
    pub kind: ReconFindingKind,
    pub name: String,
    pub value: Option<String>,
    pub record_type: Option<String>,
    pub sources: Vec<String>,
    pub discovered_at_unix: i64,
}

pub struct ReconDb {
    conn: Mutex<Connection>,
}

impl ReconDb {
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA foreign_keys=ON;\n\
             PRAGMA temp_store=MEMORY;\n\
             PRAGMA cache_size=-20000;\n\
             PRAGMA mmap_size=268435456;",
        )?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert_run(
        &self,
        id: &Uuid,
        domain: &str,
        passive_sources: &[String],
        active_enabled: bool,
    ) -> SqlResult<()> {
        let conn = self.conn.lock().expect("recon db mutex");
        conn.execute(
            "INSERT INTO recon_runs
                (id, domain, started_at, status, passive_sources,
                 active_enabled, found_subdomains, found_records)
             VALUES (?1, ?2, ?3, 'running', ?4, ?5, 0, 0)",
            params![
                id.to_string(),
                domain,
                now_secs(),
                if passive_sources.is_empty() {
                    None
                } else {
                    Some(passive_sources.join(","))
                },
                if active_enabled { 1i64 } else { 0 },
            ],
        )?;
        Ok(())
    }

    pub fn record_wildcard(&self, id: &Uuid, ips: &[String]) -> SqlResult<()> {
        let conn = self.conn.lock().expect("recon db mutex");
        conn.execute(
            "UPDATE recon_runs SET wildcard_ips = ?1 WHERE id = ?2",
            params![ips.join(","), id.to_string()],
        )?;
        Ok(())
    }

    // Kept as a single-row helper for tests and potential one-shot
    // callers. The production recon pipeline uses
    // `insert_findings_batch` to fold many events into one commit.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn insert_finding(
        &self,
        run_id: &Uuid,
        kind: ReconFindingKind,
        name: &str,
        value: Option<&str>,
        record_type: Option<&str>,
        sources: &[String],
    ) -> SqlResult<i64> {
        let conn = self.conn.lock().expect("recon db mutex");
        conn.execute(
            "INSERT INTO recon_findings
                (run_id, kind, name, value, record_type, sources, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                run_id.to_string(),
                kind.as_str(),
                name,
                value,
                record_type,
                if sources.is_empty() {
                    None
                } else {
                    Some(sources.join(","))
                },
                now_secs(),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Bulk-insert a batch of findings for one run in a single
    /// transaction. Used by the recon event loop to collapse many
    /// per-event inserts into one commit, which is dramatically
    /// cheaper on SQLite (one fsync instead of N).
    pub fn insert_findings_batch(
        &self,
        run_id: &Uuid,
        rows: &[PendingFinding],
    ) -> SqlResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().expect("recon db mutex");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO recon_findings
                    (run_id, kind, name, value, record_type, sources, discovered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            let now = now_secs();
            let run_id_s = run_id.to_string();
            for r in rows {
                stmt.execute(params![
                    run_id_s,
                    r.kind.as_str(),
                    r.name,
                    r.value,
                    r.record_type,
                    if r.sources.is_empty() {
                        None
                    } else {
                        Some(r.sources.join(","))
                    },
                    now,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn finish_run(
        &self,
        id: &Uuid,
        status: &str,
        found_subdomains: u64,
        found_records: u64,
        error: Option<&str>,
    ) -> SqlResult<()> {
        let conn = self.conn.lock().expect("recon db mutex");
        conn.execute(
            "UPDATE recon_runs
                SET ended_at = ?1,
                    status = ?2,
                    found_subdomains = ?3,
                    found_records = ?4,
                    error = ?5
              WHERE id = ?6",
            params![
                now_secs(),
                status,
                found_subdomains as i64,
                found_records as i64,
                error,
                id.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn list_runs(&self, limit: usize) -> SqlResult<Vec<ReconRunSummary>> {
        let conn = self.conn.lock().expect("recon db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT id, domain, started_at, ended_at, status,
                    passive_sources, active_enabled, wildcard_ips,
                    found_subdomains, found_records, error
               FROM recon_runs
              ORDER BY started_at DESC, id DESC
              LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let passive_sources: Option<String> = row.get(5)?;
            let wildcard_ips: Option<String> = row.get(7)?;
            let active: i64 = row.get(6)?;
            Ok(ReconRunSummary {
                id: row.get(0)?,
                domain: row.get(1)?,
                started_at_unix: row.get(2)?,
                ended_at_unix: row.get(3)?,
                status: row.get(4)?,
                passive_sources: split_csv(passive_sources),
                active_enabled: active != 0,
                wildcard_ips: split_csv(wildcard_ips),
                found_subdomains: row.get::<_, i64>(8)? as u64,
                found_records: row.get::<_, i64>(9)? as u64,
                error: row.get(10)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_run(&self, id: &Uuid) -> SqlResult<Option<ReconRunSummary>> {
        let conn = self.conn.lock().expect("recon db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT id, domain, started_at, ended_at, status,
                    passive_sources, active_enabled, wildcard_ips,
                    found_subdomains, found_records, error
               FROM recon_runs
              WHERE id = ?1",
        )?;
        stmt.query_row(params![id.to_string()], |row| {
            let passive_sources: Option<String> = row.get(5)?;
            let wildcard_ips: Option<String> = row.get(7)?;
            let active: i64 = row.get(6)?;
            Ok(ReconRunSummary {
                id: row.get(0)?,
                domain: row.get(1)?,
                started_at_unix: row.get(2)?,
                ended_at_unix: row.get(3)?,
                status: row.get(4)?,
                passive_sources: split_csv(passive_sources),
                active_enabled: active != 0,
                wildcard_ips: split_csv(wildcard_ips),
                found_subdomains: row.get::<_, i64>(8)? as u64,
                found_records: row.get::<_, i64>(9)? as u64,
                error: row.get(10)?,
            })
        })
        .optional()
    }

    pub fn findings_for_run(&self, run_id: &Uuid) -> SqlResult<Vec<ReconFindingRow>> {
        let conn = self.conn.lock().expect("recon db mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT id, run_id, kind, name, value, record_type, sources, discovered_at
               FROM recon_findings
              WHERE run_id = ?1
              ORDER BY discovered_at ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![run_id.to_string()], |row| {
            let kind_s: String = row.get(2)?;
            let sources_s: Option<String> = row.get(6)?;
            Ok(ReconFindingRow {
                id: row.get(0)?,
                run_id: row.get(1)?,
                kind: parse_finding_kind(&kind_s),
                name: row.get(3)?,
                value: row.get(4)?,
                record_type: row.get(5)?,
                sources: split_csv(sources_s),
                discovered_at_unix: row.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn delete_run(&self, id: &Uuid) -> SqlResult<usize> {
        let conn = self.conn.lock().expect("recon db mutex");
        // FK cascade takes the findings with it.
        conn.execute(
            "DELETE FROM recon_runs WHERE id = ?1",
            params![id.to_string()],
        )
        .map(|n| n as usize)
    }
}

fn split_csv(s: Option<String>) -> Vec<String> {
    s.map(|v| {
        v.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> (ReconDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "corvex-recon-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("history.sqlite");
        let db = ReconDb::open(&path).expect("open");
        (db, dir)
    }

    #[test]
    fn run_round_trip() {
        let (db, dir) = tmp_db();
        let run_id = Uuid::new_v4();
        db.insert_run(
            &run_id,
            "example.com",
            &["crt.sh".into(), "AlienVault OTX".into()],
            true,
        )
        .unwrap();

        let sub = db
            .insert_finding(
                &run_id,
                ReconFindingKind::Subdomain,
                "api.example.com",
                Some("1.2.3.4"),
                None,
                &["crt.sh".into()],
            )
            .unwrap();
        assert!(sub > 0);
        db.insert_finding(
            &run_id,
            ReconFindingKind::Record,
            "example.com",
            Some("ns1.example.com"),
            Some("NS"),
            &[],
        )
        .unwrap();

        db.finish_run(&run_id, "complete", 1, 1, None).unwrap();

        let findings = db.findings_for_run(&run_id).unwrap();
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|f| matches!(f.kind, ReconFindingKind::Subdomain)));

        let summary = db.get_run(&run_id).unwrap().unwrap();
        assert_eq!(summary.status, "complete");
        assert_eq!(summary.found_subdomains, 1);
        assert_eq!(summary.passive_sources.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cascade_on_run_delete() {
        let (db, dir) = tmp_db();
        let run_id = Uuid::new_v4();
        db.insert_run(&run_id, "example.com", &["crt.sh".into()], false)
            .unwrap();
        db.insert_finding(
            &run_id,
            ReconFindingKind::Subdomain,
            "api.example.com",
            None,
            None,
            &["crt.sh".into()],
        )
        .unwrap();

        assert_eq!(db.findings_for_run(&run_id).unwrap().len(), 1);
        assert_eq!(db.delete_run(&run_id).unwrap(), 1);
        assert!(db.get_run(&run_id).unwrap().is_none());
        assert_eq!(db.findings_for_run(&run_id).unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
