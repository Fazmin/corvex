//! SQLite-backed catalog storage.
//!
//! The runtime opens a `devices.sqlite` file (typically extracted from
//! the embedded blob in the desktop binary) and reads it into the
//! same in-memory [`DeviceCatalog`] the matcher consumes. The companion
//! `corvex-devicedb-builder` binary populates the database from the
//! YAML files in `data/devices/`.
//!
//! Schema is intentionally normalised: one row per discovery clause,
//! one row per pattern within a clause. That keeps the file
//! human-inspectable (`sqlite3 devices.sqlite '.schema'` is readable)
//! and lets future tooling query the catalog without walking compiled
//! regex objects.

use std::path::Path;

use rusqlite::{params, Connection, OpenFlags};

use crate::loader::{
    finalize, strip_pcre_delimiters, DeviceCatalog, DeviceEntry, DiscoveryClause, LoadError,
};

/// Bumped whenever the schema or compiled-row format changes. The
/// reader refuses to open a database whose version doesn't match — a
/// stale extracted copy is regenerated rather than misread.
///
/// v2 added the `iana_enterprise` and `ieee_oui` reference tables.
pub const SCHEMA_VERSION: i64 = 2;

/// Pattern-kind tag values in `device_clause_pattern.kind`. Kept as
/// `&'static str` so the same constants are referenced by writer and
/// reader without typo risk.
pub const KIND_SYS_OID: &str = "sys_object_id";
pub const KIND_SYS_OID_EXCEPT: &str = "sys_object_id_except";
pub const KIND_SYS_OID_REGEX: &str = "sys_object_id_regex";
pub const KIND_SYS_DESCR: &str = "sys_descr";
pub const KIND_SYS_DESCR_REGEX: &str = "sys_descr_regex";
pub const KIND_SYS_DESCR_EXCEPT: &str = "sys_descr_except";
pub const KIND_SYS_DESCR_REGEX_EXCEPT: &str = "sys_descr_regex_except";

/// Full DDL applied by the builder. Idempotent — the writer drops the
/// data tables before re-populating but leaves the schema alone.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS device_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_entry (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    os                  TEXT NOT NULL,
    vendor              TEXT NOT NULL,
    device_type         TEXT NOT NULL,
    max_oid_prefix_len  INTEGER NOT NULL,
    source_file         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_entry_oid_len
    ON device_entry(max_oid_prefix_len DESC);

CREATE TABLE IF NOT EXISTS device_clause (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id      INTEGER NOT NULL,
    clause_index  INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (entry_id) REFERENCES device_entry(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_device_clause_entry
    ON device_clause(entry_id);

CREATE TABLE IF NOT EXISTS device_clause_pattern (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    clause_id INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    pattern   TEXT NOT NULL,
    FOREIGN KEY (clause_id) REFERENCES device_clause(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_device_clause_pattern_clause
    ON device_clause_pattern(clause_id);

-- IANA Private Enterprise Numbers. Maps the decimal under
-- `1.3.6.1.4.1.<pen>` to the registering organisation, used as a
-- fallback vendor-identification path when no specific YAML signature
-- matches the host's sysObjectID.
CREATE TABLE IF NOT EXISTS iana_enterprise (
    pen           INTEGER PRIMARY KEY,
    organization  TEXT NOT NULL,
    contact       TEXT,
    email         TEXT
);
CREATE INDEX IF NOT EXISTS idx_iana_enterprise_org
    ON iana_enterprise(organization);

-- IEEE OUI registry. `prefix` is the upper-case hex of the first
-- N octets of the MAC (typically 6 hex chars / 24 bits, but MA-M and
-- MA-S registrations use longer prefixes). Used to resolve a MAC
-- address (when one is available — see the Datasets tab "What probing
-- does NOT collect" note) into a vendor name.
CREATE TABLE IF NOT EXISTS ieee_oui (
    prefix        TEXT PRIMARY KEY,
    organization  TEXT NOT NULL,
    address_line1 TEXT,
    address_line2 TEXT,
    country_code  TEXT
);
"#;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("schema version mismatch: db={got}, expected={expected}")]
    SchemaVersion { got: i64, expected: i64 },
    #[error("regex compile error: {pattern}: {source}")]
    Regex {
        pattern: String,
        #[source]
        source: fancy_regex::Error,
    },
    #[error("unknown pattern kind in db: {0}")]
    UnknownKind(String),
}

impl DeviceCatalog {
    /// Open a `devices.sqlite` file produced by the builder and rebuild
    /// the in-memory catalog. Regex sources are recompiled from the
    /// stored strings; OID prefixes are sorted longest-first to match
    /// the matcher's expectations.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        load_from_conn(&conn)
    }
}

fn load_from_conn(conn: &Connection) -> Result<DeviceCatalog, DbError> {
    // Verify schema version up front so a stale cache surface a clear
    // error rather than misparsed rows.
    let got: i64 = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM device_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(-1);
    if got != SCHEMA_VERSION {
        return Err(DbError::SchemaVersion {
            got,
            expected: SCHEMA_VERSION,
        });
    }

    // Pull every entry, then in a second pass attach clauses. Separate
    // queries keep the row-mapping closures simple and let SQLite cache
    // the prepared statements.
    let mut entry_stmt = conn.prepare(
        "SELECT id, os, vendor, device_type, max_oid_prefix_len
           FROM device_entry
          ORDER BY max_oid_prefix_len DESC, id ASC",
    )?;
    let entry_rows = entry_stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)? as usize,
        ))
    })?;

    let mut clause_by_entry_stmt = conn.prepare(
        "SELECT id, clause_index, disabled
           FROM device_clause
          WHERE entry_id = ?1
          ORDER BY clause_index ASC",
    )?;
    let mut pattern_by_clause_stmt = conn.prepare(
        "SELECT kind, pattern
           FROM device_clause_pattern
          WHERE clause_id = ?1",
    )?;

    let mut entries: Vec<DeviceEntry> = Vec::new();
    for entry_row in entry_rows {
        let (entry_id, os, vendor, device_type, max_oid_prefix_len) = entry_row?;
        let clause_rows = clause_by_entry_stmt.query_map(params![entry_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)? != 0,
            ))
        })?;
        let mut clauses: Vec<DiscoveryClause> = Vec::new();
        for c in clause_rows {
            let (clause_id, _idx, disabled) = c?;
            let pattern_rows = pattern_by_clause_stmt.query_map(params![clause_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut clause = DiscoveryClause {
                sys_object_id_prefixes: Vec::new(),
                sys_object_id_except_prefixes: Vec::new(),
                sys_object_id_regexes: Vec::new(),
                sys_descr_substrings: Vec::new(),
                sys_descr_regexes: Vec::new(),
                sys_descr_except: Vec::new(),
                sys_descr_regex_except: Vec::new(),
                disabled,
            };
            for p in pattern_rows {
                let (kind, pattern) = p?;
                push_pattern(&mut clause, &kind, pattern)?;
            }
            // Match the load_dir invariant: longest-prefix first.
            clause
                .sys_object_id_prefixes
                .sort_by_key(|p| std::cmp::Reverse(p.len()));
            clauses.push(clause);
        }
        entries.push(DeviceEntry {
            os,
            vendor,
            device_type,
            clauses,
            max_oid_prefix_len,
        });
    }

    finalize(&mut entries);
    Ok(DeviceCatalog { entries })
}

fn push_pattern(
    clause: &mut DiscoveryClause,
    kind: &str,
    pattern: String,
) -> Result<(), DbError> {
    match kind {
        KIND_SYS_OID => clause.sys_object_id_prefixes.push(pattern),
        KIND_SYS_OID_EXCEPT => clause.sys_object_id_except_prefixes.push(pattern),
        KIND_SYS_OID_REGEX => {
            let re = compile_regex(&pattern)?;
            clause.sys_object_id_regexes.push(re);
        }
        KIND_SYS_DESCR => clause.sys_descr_substrings.push(pattern),
        KIND_SYS_DESCR_REGEX => {
            let re = compile_regex(&pattern)?;
            clause.sys_descr_regexes.push(re);
        }
        KIND_SYS_DESCR_EXCEPT => clause.sys_descr_except.push(pattern),
        KIND_SYS_DESCR_REGEX_EXCEPT => {
            let re = compile_regex(&pattern)?;
            clause.sys_descr_regex_except.push(re);
        }
        other => return Err(DbError::UnknownKind(other.to_string())),
    }
    Ok(())
}

fn compile_regex(pattern: &str) -> Result<fancy_regex::Regex, DbError> {
    let stripped = strip_pcre_delimiters(pattern);
    fancy_regex::Regex::new(&stripped).map_err(|source| DbError::Regex {
        pattern: pattern.to_string(),
        source,
    })
}

/// Convenience for the builder: open (or create) a SQLite file at
/// `path` and apply the schema. The builder layers its writes on top.
pub fn open_for_write(path: &Path) -> Result<Connection, DbError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE;\n\
         PRAGMA synchronous=FULL;\n\
         PRAGMA foreign_keys=ON;",
    )?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Drop every data row but keep the schema, so a rerun of the builder
/// yields a deterministic file content (and matching SHA-256 if the
/// caller wants to track snapshots).
pub fn truncate(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "DELETE FROM device_clause_pattern;\n\
         DELETE FROM device_clause;\n\
         DELETE FROM device_entry;\n\
         DELETE FROM iana_enterprise;\n\
         DELETE FROM ieee_oui;\n\
         DELETE FROM device_meta;\n\
         DELETE FROM sqlite_sequence WHERE name IN \
            ('device_entry','device_clause','device_clause_pattern');",
    )?;
    Ok(())
}

/// Look up the registered organisation for a given Private Enterprise
/// Number. Cheap — `pen` is the table's primary key. Returns `None`
/// for unassigned numbers or when the lookup fails.
pub fn lookup_iana_enterprise(
    conn: &Connection,
    pen: u32,
) -> Result<Option<String>, DbError> {
    let mut stmt = conn.prepare_cached(
        "SELECT organization FROM iana_enterprise WHERE pen = ?1",
    )?;
    match stmt.query_row(params![pen as i64], |row| row.get::<_, String>(0)) {
        Ok(s) => Ok(Some(s)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Resolve a MAC address (any common spelling — colon-, dash-, dot-,
/// or no-separator hex) into the OUI organisation. Tries the longest
/// IEEE-registered MA-S (36-bit), MA-M (28-bit), and MA-L (24-bit)
/// prefixes in that order so the most specific registration wins.
pub fn lookup_ieee_oui(
    conn: &Connection,
    mac: &str,
) -> Result<Option<String>, DbError> {
    let normalised: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if normalised.len() < 6 {
        return Ok(None);
    }
    let mut stmt = conn.prepare_cached(
        "SELECT organization FROM ieee_oui WHERE prefix = ?1",
    )?;
    // IEEE registers MA-L (6 hex / 24 bits), MA-M (7 hex / 28 bits),
    // MA-S (9 hex / 36 bits). Try the longest first.
    for n in [9usize, 7, 6] {
        if normalised.len() < n {
            continue;
        }
        let prefix = &normalised[..n];
        match stmt.query_row(params![prefix], |row| row.get::<_, String>(0)) {
            Ok(s) => return Ok(Some(s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(None)
}

/// Stamp `device_meta` with the schema version + build timestamp. The
/// builder calls this last; the reader uses `schema_version` to gate
/// compatibility.
pub fn write_meta(conn: &Connection, file_count: usize) -> Result<(), DbError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    conn.execute(
        "INSERT OR REPLACE INTO device_meta (key, value) VALUES ('schema_version', ?1)",
        params![SCHEMA_VERSION],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO device_meta (key, value) VALUES ('built_at_unix', ?1)",
        params![now],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO device_meta (key, value) VALUES ('file_count', ?1)",
        params![file_count as i64],
    )?;
    Ok(())
}

/// Convert a [`LoadError`] (YAML parse / regex compile against a file
/// path) into the SQLite-flavoured error type so the builder can use
/// `?` against either source.
impl From<LoadError> for DbError {
    fn from(e: LoadError) -> Self {
        match e {
            LoadError::Io(io) => DbError::Io(io),
            LoadError::Yaml { source, .. } => DbError::Regex {
                pattern: format!("yaml: {source}"),
                source: fancy_regex::Error::ParseError(
                    0,
                    fancy_regex::ParseError::GeneralParseError(format!("yaml: {source}")),
                ),
            },
            LoadError::Regex { pattern, source, .. } => DbError::Regex { pattern, source },
        }
    }
}
