//! Runtime CSV loaders for user-supplied databases (-Userdbs).
//!
//! Uses the same quoting conventions as `build.rs` so udb_tests files
//! written against the upstream Corvex format load cleanly.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::error::{CorvexError, Result};

use super::types::*;

fn read_filtered<P: AsRef<Path>>(path: P) -> Result<String> {
    let f = File::open(path.as_ref())
        .map_err(|e| CorvexError::Config(format!("open {}: {e}", path.as_ref().display())))?;
    let mut out = String::new();
    for line in BufReader::new(f).lines() {
        let line = line.map_err(CorvexError::Io)?;
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

fn reader_from(s: &str) -> csv::Reader<&[u8]> {
    csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .quote(b'"')
        .escape(Some(b'\\'))
        .trim(csv::Trim::None)
        .from_reader(s.as_bytes())
}

/// Load a user `udb_tests` file in the same format as the shipped db_tests.
pub fn load_user_tests<P: AsRef<Path>>(path: P) -> Result<Vec<TestRow>> {
    let raw = read_filtered(path.as_ref())?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for (i, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| CorvexError::Config(format!("csv: {e}")))?;
        if i == 0
            && rec
                .get(0)
                .map(|s| s.eq_ignore_ascii_case("id") || s.eq_ignore_ascii_case("corvex_id"))
                .unwrap_or(false)
        {
            continue;
        }
        if rec.is_empty() {
            continue;
        }
        rows.push(TestRow {
            id: rec.get(0).unwrap_or_default().to_string(),
            references: rec.get(1).unwrap_or_default().to_string(),
            tuning: rec.get(2).unwrap_or_default().to_string(),
            uri: rec.get(3).unwrap_or_default().to_string(),
            method: rec.get(4).unwrap_or_default().to_string(),
            dsl: rec.get(5).unwrap_or_default().to_string(),
            message: rec.get(6).unwrap_or_default().to_string(),
            data: rec.get(7).unwrap_or_default().to_string(),
            headers: rec.get(8).unwrap_or_default().to_string(),
        });
    }
    Ok(rows)
}

/// Merge a user test DB on top of the shipped DB (both are kept).
pub fn merge_user_tests(dbs: &mut Databases, user_rows: Vec<TestRow>) {
    dbs.tests.rows.extend(user_rows);
}
