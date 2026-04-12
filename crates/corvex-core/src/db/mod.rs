//! Runtime access to the compiled Corvex databases.
//!
//! `build.rs` serializes all 14 databases into `OUT_DIR/databases.bin` at
//! compile time; we embed that blob and deserialize it lazily on first use.
//! Runtime code can also layer user-supplied CSVs on top via [`csv_loader`].

pub mod csv_loader;
pub mod types;

use once_cell::sync::Lazy;
use std::sync::Arc;

pub use types::*;

const DB_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/databases.bin"));

static DATABASES: Lazy<Arc<Databases>> = Lazy::new(|| {
    let db: Databases = bincode::deserialize(DB_BLOB)
        .expect("embedded databases.bin failed to deserialize");
    Arc::new(db)
});

/// Return the embedded databases (deserialized once, shared across threads).
pub fn load() -> Arc<Databases> {
    DATABASES.clone()
}

/// Print a one-line row count summary for every database.
/// Used by `corvex -dbcheck`.
pub fn check_summary() -> String {
    let db = load();
    format!(
        "db_tests={} db_outdated={} db_favicon={} db_server_msgs={} db_realms={} \
         db_variables={} db_content_search={} db_headers_common={} db_headers_suggested={} \
         db_multiple_index={} db_options={} db_useragents={} db_dictionary={} db_404_strings={}",
        db.tests.rows.len(),
        db.outdated.rows.len(),
        db.favicon.rows.len(),
        db.server_msgs.rows.len(),
        db.realms.rows.len(),
        db.variables.entries.len(),
        db.content_search.rows.len(),
        db.headers_common.headers.len(),
        db.headers_suggested.rows.len(),
        db.multiple_index.names.len(),
        db.options.rows.len(),
        db.useragents.agents.len(),
        db.dictionary.entries.len(),
        db.fourohfour.signatures.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_databases_load() {
        let db = load();
        assert!(db.tests.rows.len() > 1000, "db_tests should have many rows");
        assert!(!db.outdated.rows.is_empty());
        assert!(!db.favicon.rows.is_empty());
        assert!(!db.server_msgs.rows.is_empty());
        assert!(!db.realms.rows.is_empty());
        assert!(!db.variables.entries.is_empty());
    }
}
