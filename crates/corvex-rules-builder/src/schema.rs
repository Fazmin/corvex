//! SQLite schema for the unified rules catalog.

use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 1;

/// Create all tables and indices if they don't already exist, then stamp the
/// schema version into `rules_meta`.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;

        CREATE TABLE IF NOT EXISTS rules (
            rule_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            source_tool      TEXT    NOT NULL,
            source_rule_id   TEXT    NOT NULL,
            name             TEXT    NOT NULL,
            description      TEXT,
            severity         TEXT    NOT NULL,
            confidence       TEXT,
            category         TEXT,
            owasp_2025       TEXT,
            cwe              INTEGER,
            refs_json        TEXT    NOT NULL DEFAULT '[]',
            http_method      TEXT,
            uri_template     TEXT,
            request_body     TEXT,
            request_headers  TEXT,
            payloads_json    TEXT    NOT NULL DEFAULT '[]',
            detection_json   TEXT    NOT NULL,
            source_meta_json TEXT    NOT NULL DEFAULT '{}',
            enabled          INTEGER NOT NULL DEFAULT 1,
            UNIQUE (source_tool, source_rule_id)
        );

        CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
        CREATE INDEX IF NOT EXISTS idx_rules_owasp    ON rules(owasp_2025);
        CREATE INDEX IF NOT EXISTS idx_rules_source   ON rules(source_tool);
        CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);

        CREATE TABLE IF NOT EXISTS rules_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        ",
    )?;

    conn.execute(
        "INSERT INTO rules_meta (key, value) VALUES ('schema_version', ?1) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}

/// Wipe all rule rows and `rules_meta` keys that are populated by a build
/// (preserving `schema_version`). Used at the start of every full ingest so
/// reruns are reproducible.
pub fn truncate_for_rebuild(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM rules", [])?;
    conn.execute(
        "DELETE FROM rules_meta WHERE key != 'schema_version'",
        [],
    )?;
    // Reset autoincrement so rule_id starts at 1 again.
    conn.execute(
        "DELETE FROM sqlite_sequence WHERE name = 'rules'",
        [],
    )?;
    Ok(())
}
