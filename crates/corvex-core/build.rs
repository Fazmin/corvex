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
    // crates/corvex-core -> ../../program/databases
    let db_dir = manifest_dir
        .join("..")
        .join("..")
        .join("program")
        .join("databases");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/db/types.rs");
    println!("cargo:rerun-if-changed={}", db_dir.display());

    // ---- Build stamp ----
    // Every rebuild gets a fresh `CORVEX_BUILD_ID`. The ID is the short
    // git SHA if we're in a git tree, otherwise a UTC date. A `-dirty`
    // suffix is appended when the working tree has local changes. This
    // stamp drives `corvex_core::BUILD_ID` and `FULL_VERSION` — the UI
    // surfaces it in the title bar and History exports so a bug report
    // is always tied to an identifiable build.
    //
    // `cargo:rerun-if-changed=.git/HEAD` + `.git/index` means
    // `cargo build` picks up every new commit / uncommitted change
    // without forcing a full invalidation of the rest of the build
    // graph (only this script reruns, and only the few const stamps
    // are rematerialised).
    let repo_root = manifest_dir.join("..").join("..");
    let head_file = repo_root.join(".git").join("HEAD");
    let index_file = repo_root.join(".git").join("index");
    if head_file.exists() {
        println!("cargo:rerun-if-changed={}", head_file.display());
    }
    if index_file.exists() {
        println!("cargo:rerun-if-changed={}", index_file.display());
    }
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let build_id = compute_build_id(&repo_root);
    let build_date = utc_date_stamp();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let full_version = format!("{pkg_version}+{build_id}");

    println!("cargo:rustc-env=CORVEX_BUILD_ID={build_id}");
    println!("cargo:rustc-env=CORVEX_BUILD_DATE={build_date}");
    println!("cargo:rustc-env=CORVEX_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=CORVEX_FULL_VERSION={full_version}");

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
        subdomains: load_subdomains(&db_dir.join("db_subdomains"))?,
    };

    let bytes = bincode::serialize(&db).context("bincode serialize databases")?;
    std::fs::write(out_dir.join("databases.bin"), &bytes)?;

    // ---- Embed NVD+EPSS snapshot if available ----
    // Look for a pre-built compressed SQLite snapshot at program/vulndb/snapshot.db.zst
    // If present, embed it; otherwise write an empty marker file.
    let vulndb_dir = manifest_dir
        .join("..")
        .join("..")
        .join("program")
        .join("vulndb");
    println!("cargo:rerun-if-changed={}", vulndb_dir.display());

    let snapshot_candidates = [
        vulndb_dir.join("snapshot.db.gz"),
        vulndb_dir.join("snapshot.db"),
    ];
    let mut found_snapshot = false;
    for candidate in &snapshot_candidates {
        if candidate.exists() {
            let data = std::fs::read(candidate).context("read vulndb snapshot")?;
            let out_path = out_dir.join("vulndb_snapshot.bin");
            if candidate.extension().and_then(|e| e.to_str()) == Some("gz") {
                // Already compressed — copy as-is
                std::fs::write(&out_path, &data)?;
                println!(
                    "cargo:warning=corvex-core: embedded vulndb snapshot ({} bytes, gzip) from {}",
                    data.len(),
                    candidate.display()
                );
            } else {
                // Raw SQLite — compress with gzip for smaller binary
                use std::io::Write;
                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
                encoder.write_all(&data)?;
                let compressed = encoder.finish()?;
                std::fs::write(&out_path, &compressed)?;
                println!(
                    "cargo:warning=corvex-core: embedded vulndb snapshot ({} -> {} bytes gzip) from {}",
                    data.len(),
                    compressed.len(),
                    candidate.display()
                );
            }
            found_snapshot = true;
            break;
        }
    }
    if !found_snapshot {
        // Write empty marker so include_bytes! doesn't fail
        std::fs::write(out_dir.join("vulndb_snapshot.bin"), b"")?;
        println!("cargo:warning=corvex-core: no vulndb snapshot found (run scripts/build-vulndb-snapshot.sh to create one)");
    }

    println!(
        "cargo:warning=corvex-core: compiled {} tests, {} outdated, {} favicons, {} server_msgs, {} realms, {} vars, {} content, {} common hdrs, {} sugg hdrs, {} indexes, {} options, {} UAs, {} dict, {} 404 sigs, {} subdomains",
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
        db.subdomains.prefixes.len(),
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

/// Records parsed from a Nikto db file.
///
/// Replaces the old `csv::Reader` so every loader keeps its `rdr.records()`
/// loop unchanged, but the underlying split now PRESERVES regex backslashes.
/// Nikto db files (db_tests, db_outdated, db_server_msgs, …) carry regexes in
/// which `\` is a metacharacter; a CSV `escape = '\\'` setting silently
/// consumed those backslashes and rewrote the patterns (e.g. `\[winnt\]`, a
/// literal, degraded into `[winnt]`, a character class matching nearly
/// anything). See `split_nikto_csv` for the field semantics.
struct NiktoReader {
    recs: Vec<csv::StringRecord>,
}

impl NiktoReader {
    fn records(&mut self) -> impl Iterator<Item = csv::Result<csv::StringRecord>> + '_ {
        self.recs.drain(..).map(Ok)
    }
}

fn reader_from(s: &str) -> NiktoReader {
    let recs = s
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| split_nikto_csv(l).into_iter().collect::<csv::StringRecord>())
        .collect();
    NiktoReader { recs }
}

/// Split one Nikto db line into columns the way Nikto itself does.
///
/// Columns are comma-separated and optionally double-quoted. Inside a quoted
/// column `\"` is an in-field quote (it does not terminate the column), but
/// the backslash is KEPT in the value — Nikto feeds these strings straight to
/// its regex engine where `\[`, `\.`, `\s`, `\(` are meaningful. This mirrors
/// `crates/corvex-rules-builder/src/parsers/nikto.rs::split_nikto_csv`.
fn split_nikto_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        let mut field = String::new();
        if matches!(chars.peek(), Some('"')) {
            chars.next(); // opening quote
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        field.push('\\');
                        if let Some(next) = chars.next() {
                            field.push(next);
                        }
                    }
                    '"' => break,
                    other => field.push(other),
                }
            }
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                chars.next();
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                field.push(c);
                chars.next();
            }
        }
        fields.push(field);
        match chars.peek() {
            Some(',') => {
                chars.next();
                if chars.peek().is_none() {
                    fields.push(String::new());
                    break;
                }
            }
            _ => break,
        }
    }
    fields
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

fn load_subdomains(path: &Path) -> Result<SubdomainsDb> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut prefixes = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim().to_string();
        if t.is_empty() || t.starts_with('#') { continue; }
        prefixes.push(t);
    }
    Ok(SubdomainsDb { prefixes })
}

// Silence unused-import warnings in the #[path] include.
#[allow(dead_code)]
fn _ensure_read_import() -> Option<Box<dyn Read>> { None }

/* ============================================================
   Build-stamp helpers
   ============================================================ */

fn compute_build_id(repo_root: &Path) -> String {
    // Prefer git: short SHA + optional -dirty flag when the working
    // tree has any staged or unstaged changes.
    if let Some(sha) = git_short_sha(repo_root) {
        let dirty = git_is_dirty(repo_root);
        return if dirty {
            format!("{sha}-dirty")
        } else {
            sha
        };
    }
    // Fallback: SOURCE_DATE_EPOCH (reproducible-builds convention) or
    // a UTC date stamp so the build still gets a unique ID off-tree.
    if let Ok(epoch) = env::var("SOURCE_DATE_EPOCH") {
        return format!("sde.{epoch}");
    }
    format!("d{}", utc_date_stamp())
}

fn git_short_sha(repo_root: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["rev-parse", "--short=10", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    Some(t.to_string())
}

fn git_is_dirty(repo_root: &Path) -> bool {
    std::process::Command::new("git")
        .current_dir(repo_root)
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

fn utc_date_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}")
}
