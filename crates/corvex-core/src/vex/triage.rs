//! Vulnerability triage status tracking.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Triage status for a CVE finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriageStatus {
    NewFound,
    Unexplored,
    Confirmed,
    Mitigated,
    FalsePositive,
    NotAffected,
}

impl TriageStatus {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "newfound" | "new" | "n" => Some(Self::NewFound),
            "unexplored" | "u" => Some(Self::Unexplored),
            "confirmed" | "c" => Some(Self::Confirmed),
            "mitigated" | "m" => Some(Self::Mitigated),
            "falsepositive" | "false_positive" | "fp" | "f" => Some(Self::FalsePositive),
            "notaffected" | "not_affected" | "na" | "i" => Some(Self::NotAffected),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NewFound => "new_found",
            Self::Unexplored => "unexplored",
            Self::Confirmed => "confirmed",
            Self::Mitigated => "mitigated",
            Self::FalsePositive => "false_positive",
            Self::NotAffected => "not_affected",
        }
    }

    /// Whether this status should suppress the CVE from output.
    pub fn is_suppressed(&self) -> bool {
        matches!(self, Self::FalsePositive | Self::NotAffected)
    }
}

impl std::fmt::Display for TriageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A triage entry for a specific CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageEntry {
    pub cve_id: String,
    pub component: Option<String>,
    pub status: TriageStatus,
    pub justification: Option<String>,
    pub updated_at: i64,
}

/// SQLite-backed triage database.
pub struct TriageDb {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    path: PathBuf,
}

impl TriageDb {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create dir: {e}"))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| format!("open triage db: {e}"))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS triage_entries (
                cve_id        TEXT NOT NULL,
                component     TEXT,
                status        TEXT NOT NULL,
                justification TEXT,
                updated_at    INTEGER NOT NULL,
                PRIMARY KEY (cve_id, component)
            );",
        )
        .map_err(|e| format!("create table: {e}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// Open the default triage database.
    pub fn open_default() -> Result<Self, String> {
        let path = default_triage_path()?;
        Self::open(&path)
    }

    /// Set triage status for a CVE.
    pub fn set_status(
        &self,
        cve_id: &str,
        component: Option<&str>,
        status: TriageStatus,
        justification: Option<&str>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        conn.execute(
            "INSERT OR REPLACE INTO triage_entries (cve_id, component, status, justification, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![cve_id, component.unwrap_or(""), status.as_str(), justification, now],
        )
        .map_err(|e| format!("set triage: {e}"))?;
        Ok(())
    }

    /// Get triage status for a CVE.
    pub fn get_status(&self, cve_id: &str, component: Option<&str>) -> Result<Option<TriageEntry>, String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cve_id, component, status, justification, updated_at
             FROM triage_entries WHERE cve_id = ?1 AND component = ?2",
            rusqlite::params![cve_id, component.unwrap_or("")],
            |row| {
                let status_str: String = row.get(2)?;
                Ok(TriageEntry {
                    cve_id: row.get(0)?,
                    component: row.get(1)?,
                    status: TriageStatus::parse(&status_str).unwrap_or(TriageStatus::Unexplored),
                    justification: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| format!("get triage: {e}"))
    }

    /// Get all triage entries.
    pub fn all_entries(&self) -> Result<Vec<TriageEntry>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT cve_id, component, status, justification, updated_at FROM triage_entries")
            .map_err(|e| format!("prepare: {e}"))?;

        let entries = stmt
            .query_map([], |row| {
                let status_str: String = row.get(2)?;
                Ok(TriageEntry {
                    cve_id: row.get(0)?,
                    component: row.get(1)?,
                    status: TriageStatus::parse(&status_str).unwrap_or(TriageStatus::Unexplored),
                    justification: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            })
            .map_err(|e| format!("query: {e}"))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(entries)
    }

    /// Check if a CVE should be suppressed based on triage status.
    pub fn is_suppressed(&self, cve_id: &str, component: Option<&str>) -> bool {
        self.get_status(cve_id, component)
            .ok()
            .flatten()
            .map(|e| e.status.is_suppressed())
            .unwrap_or(false)
    }
}

fn default_triage_path() -> Result<PathBuf, String> {
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
    Ok(dir.join("triage.sqlite"))
}

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
