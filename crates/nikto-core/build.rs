//! Build script: convert every db_* CSV in ../../program/databases/ into a
//! single bincode blob stored in OUT_DIR, which the runtime loads once at
//! startup via include_bytes!.

#[path = "src/db/types.rs"]
mod types;

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use types::*;

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    // crates/nikto-core -> ../../program/databases
    let db_dir = manifest_dir
        .join("..")
        .join("..")
        .join("program")
        .join("databases");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/db/types.rs");
    println!("cargo:rerun-if-changed={}", db_dir.display());

    let db = Databases {
        tests: load_tests(&db_dir.join("db_tests"))?,
        outdated: load_outdated(&db_dir.join("db_outdated"))?,
        favicon: load_favicon(&db_dir.join("db_favicon"))?,
        server_msgs: load_server_msgs(&db_dir.join("db_server_msgs"))?,
        realms: load_realms(&db_dir.join("db_realms"))?,
        variables: load_variables(&db_dir.join("db_variables"))?,
        content_search: load_content_search(&db_dir.join("db_content_search"))?,
        headers_common: load_headers_common(&db_dir.join("db_headers_common"))?,
        headers_suggested: load_headers_suggested(&db_dir.join("db_headers_suggested"))?,
        multiple_index: load_multiple_index(&db_dir.join("db_multiple_index"))?,
        options: load_options(&db_dir.join("db_options"))?,
        useragents: load_useragents(&db_dir.join("db_useragents"))?,
        dictionary: load_dictionary(&db_dir.join("db_dictionary"))?,
        fourohfour: load_fourohfour(&db_dir.join("db_404_strings"))?,
    };

    let bytes = bincode::serialize(&db).context("bincode serialize databases")?;
    std::fs::write(out_dir.join("databases.bin"), &bytes)?;

    println!(
        "cargo:warning=nikto-core: compiled {} tests, {} outdated, {} favicons, {} server_msgs, {} realms, {} vars, {} content, {} common hdrs, {} sugg hdrs, {} indexes, {} options, {} UAs, {} dict, {} 404 sigs",
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
    );

    Ok(())
}

// ----- Helpers ---------------------------------------------------------------

fn read_filtered(path: &Path) -> Result<String> {
    // Strip comment/blank lines before handing to csv crate. db files have
    // a shared banner of `#` lines at the top and occasional `#` comments.
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut out = String::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
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

// ----- Per-DB loaders --------------------------------------------------------

fn load_tests(path: &Path) -> Result<TestDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for (i, rec) in rdr.records().enumerate() {
        let rec = rec.with_context(|| format!("db_tests row {}", i))?;
        // Skip potential CSV header row
        if i == 0 && rec.get(0).map(|s| s.eq_ignore_ascii_case("id") || s.eq_ignore_ascii_case("nikto_id")).unwrap_or(false) {
            continue;
        }
        if rec.len() < 1 {
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
    Ok(TestDb { rows })
}

fn load_outdated(path: &Path) -> Result<OutdatedDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 4 { continue; }
        if rec.get(0).unwrap_or("").eq_ignore_ascii_case("nikto_id") { continue; }
        rows.push(OutdatedRow {
            id: rec.get(0).unwrap_or_default().to_string(),
            server_regex: rec.get(1).unwrap_or_default().to_string(),
            version: rec.get(2).unwrap_or_default().to_string(),
            message: rec.get(3).unwrap_or_default().to_string(),
        });
    }
    Ok(OutdatedDb { rows })
}

fn load_favicon(path: &Path) -> Result<FaviconDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 3 { continue; }
        if rec.get(0).unwrap_or("").eq_ignore_ascii_case("nikto_id") { continue; }
        rows.push(FaviconRow {
            id: rec.get(0).unwrap_or_default().to_string(),
            md5: rec.get(1).unwrap_or_default().to_string(),
            description: rec.get(2).unwrap_or_default().to_string(),
        });
    }
    Ok(FaviconDb { rows })
}

fn load_server_msgs(path: &Path) -> Result<ServerMsgsDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 4 { continue; }
        if rec.get(0).unwrap_or("").eq_ignore_ascii_case("nikto_id") { continue; }
        rows.push(ServerMsgRow {
            id: rec.get(0).unwrap_or_default().to_string(),
            server_regex: rec.get(1).unwrap_or_default().to_string(),
            reference: rec.get(2).unwrap_or_default().to_string(),
            message: rec.get(3).unwrap_or_default().to_string(),
        });
    }
    Ok(ServerMsgsDb { rows })
}

fn load_realms(path: &Path) -> Result<RealmsDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 5 { continue; }
        if rec.get(0).unwrap_or("").eq_ignore_ascii_case("nikto_id") { continue; }
        rows.push(RealmRow {
            id: rec.get(0).unwrap_or_default().to_string(),
            realm: rec.get(1).unwrap_or_default().to_string(),
            user: rec.get(2).unwrap_or_default().to_string(),
            password: rec.get(3).unwrap_or_default().to_string(),
            message: rec.get(4).unwrap_or_default().to_string(),
        });
    }
    Ok(RealmsDb { rows })
}

fn load_variables(path: &Path) -> Result<VariablesDb> {
    // Format: "@NAME=value1 value2 value3" — one per line, not CSV.
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut entries = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        let stripped = t.strip_prefix('@').unwrap_or(t);
        let (name, rest) = match stripped.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        let values: Vec<String> = rest.split_whitespace().map(|s| s.to_string()).collect();
        entries.push((name.to_string(), values));
    }
    Ok(VariablesDb { entries })
}

fn load_content_search(path: &Path) -> Result<ContentSearchDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 4 { continue; }
        if rec.get(0).unwrap_or("").eq_ignore_ascii_case("nikto_id") { continue; }
        rows.push(ContentSearchRow {
            id: rec.get(0).unwrap_or_default().to_string(),
            references: rec.get(1).unwrap_or_default().to_string(),
            matchstring: rec.get(2).unwrap_or_default().to_string(),
            message: rec.get(3).unwrap_or_default().to_string(),
        });
    }
    Ok(ContentSearchDb { rows })
}

fn load_headers_common(path: &Path) -> Result<HeadersCommonDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut headers = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        let v = rec.get(0).unwrap_or_default().trim().to_string();
        if v.is_empty() || v.eq_ignore_ascii_case("header") { continue; }
        headers.push(v);
    }
    Ok(HeadersCommonDb { headers })
}

fn load_headers_suggested(path: &Path) -> Result<HeadersSuggestedDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 2 { continue; }
        let header = rec.get(0).unwrap_or_default().to_string();
        if header.eq_ignore_ascii_case("header") { continue; }
        rows.push(HeaderSuggestedRow {
            header,
            reference: rec.get(1).unwrap_or_default().to_string(),
        });
    }
    Ok(HeadersSuggestedDb { rows })
}

fn load_multiple_index(path: &Path) -> Result<MultipleIndexDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut names = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        let v = rec.get(0).unwrap_or_default().trim().to_string();
        if v.is_empty() || v.eq_ignore_ascii_case("index") { continue; }
        names.push(v);
    }
    Ok(MultipleIndexDb { names })
}

fn load_options(path: &Path) -> Result<OptionsDb> {
    let raw = read_filtered(path)?;
    let mut rdr = reader_from(&raw);
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 4 { continue; }
        if rec.get(0).unwrap_or("").eq_ignore_ascii_case("nikto_id") { continue; }
        rows.push(OptionRow {
            id: rec.get(0).unwrap_or_default().to_string(),
            method: rec.get(1).unwrap_or_default().to_string(),
            references: rec.get(2).unwrap_or_default().to_string(),
            message: rec.get(3).unwrap_or_default().to_string(),
        });
    }
    Ok(OptionsDb { rows })
}

fn load_useragents(path: &Path) -> Result<UseragentsDb> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut agents = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        // Strip surrounding quotes
        let cleaned = t.trim_matches('"').to_string();
        if !cleaned.is_empty() {
            agents.push(cleaned);
        }
    }
    Ok(UseragentsDb { agents })
}

fn load_dictionary(path: &Path) -> Result<DictionaryDb> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut entries = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim().to_string();
        if t.is_empty() || t.starts_with('#') { continue; }
        entries.push(t);
    }
    Ok(DictionaryDb { entries })
}

fn load_fourohfour(path: &Path) -> Result<FourOhFourDb> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut signatures = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim().to_string();
        if t.is_empty() || t.starts_with('#') { continue; }
        signatures.push(t);
    }
    Ok(FourOhFourDb { signatures })
}

// Silence unused-import warnings in the #[path] include.
#[allow(dead_code)]
fn _ensure_read_import() -> Option<Box<dyn Read>> { None }
