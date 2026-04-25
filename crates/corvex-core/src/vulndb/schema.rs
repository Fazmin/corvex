//! SQLite schema definition and migration logic.

use rusqlite::Connection;

/// Current schema version.
///
/// v2 adds materialised `vendor` / `product` columns + index on
/// `cpe_matches`. Without these, `lookup_component` had to do a
/// full-table scan + parse-the-CPE-URI-in-Rust per component, which
/// on a 1k-component SCA run took ~10 minutes. With the index it's
/// a few seconds.
pub const SCHEMA_VERSION: u32 = 2;

/// Create all tables if they don't exist, and run migrations.
///
/// Order matters here: on an existing v1 database the `cpe_matches`
/// table already exists *without* the `vendor` / `product` columns,
/// and `CREATE TABLE IF NOT EXISTS` is a no-op. So we must:
///   1. create tables / non-vendor indices first,
///   2. ALTER TABLE to add the new columns if they're missing,
///   3. *then* create the (vendor, product) partial index.
/// Doing #3 inside the same `execute_batch` as the CREATE TABLE was
/// the bug — SQLite parses the whole batch up front and rejects
/// statements that reference columns the running schema doesn't yet
/// have, even with IF NOT EXISTS.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    // 1. Tables + version-stable indices.
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
            vendor                   TEXT,
            product                  TEXT,
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

    // 2. Add vendor/product columns to pre-existing v1 tables. SQLite
    //    has no "ADD COLUMN IF NOT EXISTS" — probe pragma first.
    let has_vendor: bool = conn
        .query_row(
            "SELECT 1 FROM pragma_table_info('cpe_matches') WHERE name = 'vendor'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !has_vendor {
        conn.execute("ALTER TABLE cpe_matches ADD COLUMN vendor TEXT", [])?;
    }
    let has_product: bool = conn
        .query_row(
            "SELECT 1 FROM pragma_table_info('cpe_matches') WHERE name = 'product'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !has_product {
        conn.execute("ALTER TABLE cpe_matches ADD COLUMN product TEXT", [])?;
    }

    // 3. Now (with the columns guaranteed to exist) create the
    //    composite partial index.
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_cpe_matches_vp \
             ON cpe_matches(vendor, product) WHERE vulnerable = 1;",
    )?;

    // Set schema version (overwrite — older DBs may have version=1).
    conn.execute(
        "INSERT INTO db_meta (key, value) VALUES ('schema_version', ?1) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}
