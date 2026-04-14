//! SQLite schema definition and migration logic.

use rusqlite::Connection;

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Create all tables if they don't exist, and run migrations.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS db_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cves (
            cve_id            TEXT PRIMARY KEY,
            description       TEXT NOT NULL DEFAULT '',
            published         TEXT,
            modified          TEXT,
            cvss_v31_score    REAL,
            cvss_v31_vector   TEXT,
            severity          TEXT,
            source            TEXT NOT NULL DEFAULT 'nvd'
        );

        CREATE TABLE IF NOT EXISTS cpe_matches (
            id                       INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id                   TEXT NOT NULL,
            cpe23_uri                TEXT NOT NULL,
            vulnerable               INTEGER NOT NULL DEFAULT 1,
            version_start_including  TEXT,
            version_start_excluding  TEXT,
            version_end_including    TEXT,
            version_end_excluding    TEXT,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE INDEX IF NOT EXISTS idx_cpe_matches_cve
            ON cpe_matches(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cpe_matches_cpe
            ON cpe_matches(cpe23_uri);

        CREATE TABLE IF NOT EXISTS cve_references (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            url    TEXT NOT NULL,
            source TEXT,
            tags   TEXT DEFAULT '',
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE INDEX IF NOT EXISTS idx_cve_refs_cve
            ON cve_references(cve_id);

        CREATE TABLE IF NOT EXISTS epss_scores (
            cve_id     TEXT PRIMARY KEY,
            score      REAL NOT NULL,
            percentile REAL NOT NULL,
            date       TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS fixes (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id        TEXT NOT NULL,
            ecosystem     TEXT,
            package       TEXT,
            fixed_version TEXT NOT NULL,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE INDEX IF NOT EXISTS idx_fixes_cve
            ON fixes(cve_id);
        ",
    )?;

    // Set schema version if not present.
    conn.execute(
        "INSERT OR IGNORE INTO db_meta (key, value) VALUES ('schema_version', ?1)",
        rusqlite::params![SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}
