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
    pub saved: bool,
}

/// One row from `scan_findings`. Field names match the UI's
/// `FindingPayload` 1:1 so the list query serializes straight into the
/// shape `<FindingsTable>` already consumes.
#[derive(Debug, Clone, Serialize)]
pub struct ScanFindingRow {
    pub host: String,
    pub port: i64,
    pub corvex_id: String,
    pub method: String,
    pub uri: String,
    pub message: String,
    pub refs: String,
    pub plugin: String,
    pub severity: String,
    pub cve: Option<String>,
    pub cvss: Option<f64>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub fix_version: Option<String>,
    pub component: Option<String>,
    pub component_version: Option<String>,
    pub details: Option<String>,
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
    total_errors    INTEGER NOT NULL DEFAULT 0,
    saved           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at DESC);

-- Per-finding persistence for dashboard web-vulnerability scans. The
-- proxy/checks pipeline writes its findings to exchange_scan_findings
-- (keyed by exchange_id); the dashboard scan engine has no exchange
-- context, so its rows live here keyed by scan_id + host. The asset
-- view unions both tables when rendering Findings for an asset.
CREATE TABLE IF NOT EXISTS scan_findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id            INTEGER,
    host               TEXT NOT NULL,
    port               INTEGER NOT NULL DEFAULT 0,
    method             TEXT,
    uri                TEXT NOT NULL DEFAULT '',
    plugin             TEXT NOT NULL DEFAULT '',
    corvex_id          TEXT,
    severity           TEXT NOT NULL DEFAULT 'INFO',
    message            TEXT NOT NULL DEFAULT '',
    refs               TEXT,
    cve                TEXT,
    cvss               REAL,
    epss_score         REAL,
    epss_percentile    REAL,
    fix_version        TEXT,
    component          TEXT,
    component_version  TEXT,
    details            TEXT,
    created_at         INTEGER NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scan_findings_host ON scan_findings(host);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id);
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
        // foreign_keys=ON is required for `scan_findings.scan_id`'s
        // `ON DELETE CASCADE` to actually fire when a scan is deleted.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             PRAGMA temp_store=MEMORY;\n\
             PRAGMA cache_size=-20000;\n\
             PRAGMA mmap_size=268435456;\n\
             PRAGMA foreign_keys=ON;",
        )?;

        // Migration for DBs created before the `saved` opt-in flag: add
        // the column with default 0 if it isn't already there.
        let has_saved: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('scans') WHERE name = 'saved'")?
            .query_row([], |_| Ok(true))
            .unwrap_or(false);
        if !has_saved {
            conn.execute(
                "ALTER TABLE scans ADD COLUMN saved INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }

        // Migration for DBs created before per-finding `details` JSON.
        let has_details: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('scan_findings') WHERE name = 'details'")?
            .query_row([], |_| Ok(true))
            .unwrap_or(false);
        if !has_details {
            conn.execute("ALTER TABLE scan_findings ADD COLUMN details TEXT", [])?;
        }

        // Opt-in retention: anything not explicitly saved by the user
        // gets dropped at app launch. Cascades through `scan_findings`.
        conn.execute("DELETE FROM scans WHERE saved = 0", [])?;

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
        // Only saved scans are surfaced. Unsaved rows live in the DB
        // until the next launch, then `purge_unsaved` (run inside `open`)
        // drops them. We also include any in-flight `running` scan so a
        // user who opens History mid-scan still sees it.
        let mut stmt = conn.prepare_cached(
            "SELECT id, host, params_json, started_at, ended_at, status,
                    total_requests, total_findings, total_errors, saved
               FROM scans
              WHERE saved = 1 OR status = 'running'
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
                saved: row.get::<_, i64>(9)? != 0,
            })
        })?;
        rows.collect()
    }

    pub fn set_saved(&self, id: i64, saved: bool) -> SqlResult<usize> {
        let conn = self.conn.lock().expect("history mutex");
        conn.execute(
            "UPDATE scans SET saved = ?1 WHERE id = ?2",
            params![saved as i64, id],
        )
    }

    /// Return every `scan_findings` row for a given scan. Callers map
    /// this directly into the UI's `FindingPayload` shape.
    pub fn list_findings(&self, scan_id: i64) -> SqlResult<Vec<ScanFindingRow>> {
        let conn = self.conn.lock().expect("history mutex");
        let mut stmt = conn.prepare_cached(
            "SELECT host, port, corvex_id, method, uri, message, refs,
                    plugin, severity, cve, cvss, epss_score,
                    epss_percentile, fix_version, component,
                    component_version, details
               FROM scan_findings
              WHERE scan_id = ?1
              ORDER BY id",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok(ScanFindingRow {
                host: row.get(0)?,
                port: row.get(1)?,
                corvex_id: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                method: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                uri: row.get(4)?,
                message: row.get(5)?,
                refs: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                plugin: row.get(7)?,
                severity: row.get(8)?,
                cve: row.get(9)?,
                cvss: row.get(10)?,
                epss_score: row.get(11)?,
                epss_percentile: row.get(12)?,
                fix_version: row.get(13)?,
                component: row.get(14)?,
                component_version: row.get(15)?,
                details: row.get(16)?,
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

    /// Persist one dashboard-scan finding so it shows up in the asset
    /// Findings panel for the matching host. Called from
    /// `TauriEventSink::item` per finding — the prepared statement
    /// keeps this fast enough to run synchronously inside the scan
    /// pipeline.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_scan_finding(
        &self,
        scan_id: Option<i64>,
        host: &str,
        port: u16,
        method: Option<&str>,
        uri: &str,
        plugin: &str,
        corvex_id: Option<&str>,
        severity: &str,
        message: &str,
        refs: Option<&str>,
        cve: Option<&str>,
        cvss: Option<f32>,
        epss_score: Option<f32>,
        epss_percentile: Option<f32>,
        fix_version: Option<&str>,
        component: Option<&str>,
        component_version: Option<&str>,
        details: Option<&str>,
    ) -> SqlResult<()> {
        let conn = self.conn.lock().expect("history mutex");
        let mut stmt = conn.prepare_cached(
            "INSERT INTO scan_findings
                (scan_id, host, port, method, uri, plugin, corvex_id,
                 severity, message, refs, cve, cvss, epss_score,
                 epss_percentile, fix_version, component,
                 component_version, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        )?;
        stmt.execute(params![
            scan_id,
            host,
            port as i64,
            method,
            uri,
            plugin,
            corvex_id,
            severity,
            message,
            refs,
            cve,
            cvss.map(|v| v as f64),
            epss_score.map(|v| v as f64),
            epss_percentile.map(|v| v as f64),
            fix_version,
            component,
            component_version,
            details,
            now_secs(),
        ])?;
        Ok(())
    }
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
