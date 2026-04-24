//! On-disk scan history persisted in a bundled SQLite database.
//!
//! The DB lives at the platform's `app_data_dir` (e.g. `%APPDATA%\
//! dev.fazminnizam.corvex-rust\history.sqlite` on Windows). Schema is
//! created on first open via `CREATE TABLE IF NOT EXISTS`, so existing
//! files keep working across upgrades.
//!
//! Only scan summaries are stored — host, params, counts, status,
//! timestamps. Full per-finding data lives only in the file report
//! sinks (json/html/csv/…) the user picks at scan time. The summary
//! is enough to power the History view's "what did I scan and when"
//! workflow without bloating the DB.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, Result as SqlResult};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub host: String,
    pub params_json: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub status: String,
    pub total_requests: i64,
    pub total_findings: i64,
    pub total_errors: i64,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host            TEXT    NOT NULL,
    params_json     TEXT    NOT NULL,
    started_at      INTEGER NOT NULL,
    ended_at        INTEGER,
    status          TEXT    NOT NULL DEFAULT 'running',
    total_requests  INTEGER NOT NULL DEFAULT 0,
    total_findings  INTEGER NOT NULL DEFAULT 0,
    total_errors    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at DESC);
"#;

pub struct HistoryDb {
    conn: Mutex<Connection>,
}

impl HistoryDb {
    pub fn open<P: AsRef<Path>>(path: P) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        // PRAGMAs: WAL gives concurrent reader/writer access; synchronous
        // NORMAL is WAL-safe and much faster than the default FULL.
        // temp_store=MEMORY avoids temp-file spills; the cache and mmap
        // sizes speed up list/filter queries once the DB grows.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA temp_store=MEMORY;\n\
             PRAGMA cache_size=-20000;\n\
             PRAGMA mmap_size=268435456;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert_scan(&self, host: &str, params_json: &str) -> SqlResult<i64> {
        let now = now_secs();
        let conn = self.conn.lock().expect("history mutex");
        conn.execute(
            "INSERT INTO scans (host, params_json, started_at, status) VALUES (?1, ?2, ?3, 'running')",
            params![host, params_json, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn finish_scan(
        &self,
        id: i64,
        status: &str,
        total_requests: u64,
        total_findings: u64,
        total_errors: u64,
    ) -> SqlResult<()> {
        let now = now_secs();
        let conn = self.conn.lock().expect("history mutex");
        conn.execute(
            "UPDATE scans
                SET ended_at = ?1,
                    status = ?2,
                    total_requests = ?3,
                    total_findings = ?4,
                    total_errors = ?5
              WHERE id = ?6",
            params![
                now,
                status,
                total_requests as i64,
                total_findings as i64,
                total_errors as i64,
                id
            ],
        )?;
        Ok(())
    }

    pub fn list(&self, limit: usize) -> SqlResult<Vec<HistoryEntry>> {
        let conn = self.conn.lock().expect("history mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT id, host, params_json, started_at, ended_at, status,
                    total_requests, total_findings, total_errors
               FROM scans
              ORDER BY started_at DESC
              LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(HistoryEntry {
                id: row.get(0)?,
                host: row.get(1)?,
                params_json: row.get(2)?,
                started_at: row.get(3)?,
                ended_at: row.get(4)?,
                status: row.get(5)?,
                total_requests: row.get(6)?,
                total_findings: row.get(7)?,
                total_errors: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    pub fn clear(&self) -> SqlResult<usize> {
        let conn = self.conn.lock().expect("history mutex");
        conn.execute("DELETE FROM scans", [])
    }

    pub fn delete(&self, id: i64) -> SqlResult<usize> {
        let conn = self.conn.lock().expect("history mutex");
        conn.execute("DELETE FROM scans WHERE id = ?1", params![id])
    }
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
