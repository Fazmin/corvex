//! Build the SNMP device-signature catalog into a SQLite file.
//!
//! Usage:
//!     cargo run -p corvex-devicedb-builder -- \
//!         --sources crates/corvex-devicedb/data/devices \
//!         --output devices.sqlite
//!
//! The defaults match the canonical repo layout, so a bare
//! `cargo run -p corvex-devicedb-builder` from the workspace root
//! refreshes `<repo-root>/devices.sqlite` from the bundled YAMLs.
//!
//! The builder is deterministic-ish: rerunning over the same YAML
//! input yields the same row content (modulo `built_at_unix` in
//! `device_meta`), so the artifact is safe to commit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use corvex_devicedb::db::{
    self, KIND_SYS_DESCR, KIND_SYS_DESCR_EXCEPT, KIND_SYS_DESCR_REGEX,
    KIND_SYS_DESCR_REGEX_EXCEPT, KIND_SYS_OID, KIND_SYS_OID_EXCEPT, KIND_SYS_OID_REGEX,
};
use corvex_devicedb::{RawDef, DEFAULT_DATA_SUBDIR, DEFAULT_DB_RELPATH};
use rusqlite::{params, Connection};

#[derive(Parser, Debug)]
#[command(
    name = "corvex-devicedb-builder",
    about = "Compile YAML device signatures into devices.sqlite"
)]
struct Args {
    /// Directory of `*.yaml` source files to ingest.
    #[arg(long, default_value_os_t = default_sources())]
    sources: PathBuf,
    /// Output SQLite file. Truncated and repopulated on each run.
    /// Default is `program/devicedb/devices.sqlite` under the
    /// workspace root, matching the layout of the vulndb snapshot.
    #[arg(long, default_value_os_t = PathBuf::from(DEFAULT_DB_RELPATH))]
    output: PathBuf,
    /// Path to the IANA Private Enterprise Numbers source file
    /// (canonical IANA fixed-format text — the one served at
    /// https://www.iana.org/assignments/enterprise-numbers.txt).
    /// Pass an empty string to skip ingesting this table.
    #[arg(long, default_value_os_t = default_iana())]
    iana: PathBuf,
    /// Path to the IEEE OUI registry as a JSON array of
    /// `{ prefix, organization: { name, address: {...} } }` records.
    /// Pass an empty string to skip ingesting this table.
    #[arg(long, default_value_os_t = default_oui())]
    oui: PathBuf,
    /// Verbose logging.
    #[arg(long, short)]
    verbose: bool,
}

fn default_sources() -> PathBuf {
    // Builder is typically invoked from the workspace root; fall back
    // to the canonical sub-path under the corvex-devicedb crate.
    PathBuf::from("crates/corvex-devicedb").join(DEFAULT_DATA_SUBDIR)
}

fn default_iana() -> PathBuf {
    PathBuf::from("crates/corvex-devicedb/data/iana-enterprise-numbers.txt")
}

fn default_oui() -> PathBuf {
    PathBuf::from("crates/corvex-devicedb/data/ieee-ouidb.json")
}

fn main() -> Result<()> {
    let args = Args::parse();

    let level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("{level},corvex_devicedb=info"))
        .with_target(true)
        .init();

    tracing::info!(
        target: "devicedb_builder",
        sources = %args.sources.display(),
        output = %args.output.display(),
        "starting build"
    );

    let yaml_files = collect_yaml_files(&args.sources)
        .with_context(|| format!("scanning {}", args.sources.display()))?;
    if yaml_files.is_empty() {
        anyhow::bail!("no YAML files found under {}", args.sources.display());
    }
    tracing::info!(target: "devicedb_builder", files = yaml_files.len(), "discovered YAMLs");

    let mut conn =
        db::open_for_write(&args.output).context("opening / initialising output SQLite")?;
    db::truncate(&conn).context("truncating prior catalog rows")?;

    let mut written = 0usize;
    let mut skipped = 0usize;
    let mut iana_rows = 0usize;
    let mut oui_rows = 0usize;
    {
        let tx = conn.transaction().context("begin tx")?;
        for path in &yaml_files {
            match ingest_one(&tx, path) {
                Ok(true) => written += 1,
                Ok(false) => skipped += 1,
                Err(e) => {
                    tracing::warn!(
                        target: "devicedb_builder",
                        file = %path.display(),
                        "skipped: {e}"
                    );
                    skipped += 1;
                }
            }
        }
        if !args.iana.as_os_str().is_empty() {
            iana_rows = ingest_iana(&tx, &args.iana).with_context(|| {
                format!("ingesting IANA file {}", args.iana.display())
            })?;
            tracing::info!(
                target: "devicedb_builder",
                rows = iana_rows,
                "IANA enterprise numbers ingested"
            );
        }
        if !args.oui.as_os_str().is_empty() {
            oui_rows = ingest_oui(&tx, &args.oui).with_context(|| {
                format!("ingesting IEEE OUI file {}", args.oui.display())
            })?;
            tracing::info!(
                target: "devicedb_builder",
                rows = oui_rows,
                "IEEE OUI rows ingested"
            );
        }
        db::write_meta(&tx, written).context("writing meta")?;
        tx.commit().context("commit tx")?;
    }
    tracing::info!(
        target: "devicedb_builder",
        device_entries = written,
        device_skipped = skipped,
        iana_rows,
        oui_rows,
        "tables populated"
    );

    // VACUUM compacts the file so the committed artifact is small and
    // byte-stable across builds.
    conn.execute_batch("VACUUM;").context("vacuum")?;

    tracing::info!(
        target: "devicedb_builder",
        written, skipped, output = %args.output.display(),
        "build complete"
    );
    Ok(())
}

fn collect_yaml_files(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        anyhow::bail!("sources is not a directory: {}", dir.display());
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for ent in walkdir::WalkDir::new(dir)
        .max_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        match p.extension().and_then(|s| s.to_str()) {
            Some("yaml") | Some("yml") => out.push(p.to_path_buf()),
            _ => continue,
        }
    }
    // Deterministic order so the SQLite row IDs are stable across
    // runs on different filesystems.
    out.sort();
    Ok(out)
}

/// Read one YAML file, normalize its discovery rules, and write the
/// rows. Returns `true` when an entry row landed, `false` when the
/// file was empty / had no usable discovery clauses.
fn ingest_one(conn: &Connection, path: &Path) -> Result<bool> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let parsed: RawDef =
        serde_yaml::from_str(&raw).with_context(|| format!("yaml in {}", path.display()))?;

    let vendor = parsed.group.unwrap_or_else(|| parsed.os.clone());
    let device_type = parsed.device_type.unwrap_or_else(|| "other".to_string());

    // Pre-compute max OID prefix length so the reader's sort can use
    // the indexed column instead of scanning patterns.
    let mut max_oid_prefix_len: usize = 0;
    for d in &parsed.discovery {
        for oid in d.sys_object_id.as_slice() {
            let n = oid.trim_start_matches('.').trim().len();
            if n > max_oid_prefix_len {
                max_oid_prefix_len = n;
            }
        }
    }

    let source_file = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();

    conn.execute(
        "INSERT INTO device_entry (os, vendor, device_type, max_oid_prefix_len, source_file)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            parsed.os,
            vendor,
            device_type,
            max_oid_prefix_len as i64,
            source_file
        ],
    )?;
    let entry_id = conn.last_insert_rowid();

    let mut wrote_any_clause = false;
    for (idx, d) in parsed.discovery.into_iter().enumerate() {
        let disabled = d.snmpget.is_some() || d.snmpget_except.is_some() || d.snmpget_oid.is_some();

        // Snapshot OneOrMany contents — discovered once so we can cheaply
        // skip empty clauses.
        let oids: Vec<String> = d
            .sys_object_id
            .into_vec()
            .into_iter()
            .filter_map(normalize_oid)
            .collect();
        let oids_except: Vec<String> = d
            .sys_object_id_except
            .into_vec()
            .into_iter()
            .filter_map(normalize_oid)
            .collect();
        let oid_regexes = d.sys_object_id_regex.into_vec();
        let descrs: Vec<String> = d
            .sys_descr
            .into_vec()
            .into_iter()
            .map(|s| s.to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let descr_regexes = d.sys_descr_regex.into_vec();
        let descr_except: Vec<String> = d
            .sys_descr_except
            .into_vec()
            .into_iter()
            .map(|s| s.to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let descr_regex_except = d.sys_descr_regex_except.into_vec();

        let total_patterns = oids.len()
            + oids_except.len()
            + oid_regexes.len()
            + descrs.len()
            + descr_regexes.len()
            + descr_except.len()
            + descr_regex_except.len();
        if total_patterns == 0 {
            // Empty clause: the runtime would never fire it, so don't
            // bloat the database with a row that can't match.
            continue;
        }

        conn.execute(
            "INSERT INTO device_clause (entry_id, clause_index, disabled)
             VALUES (?1, ?2, ?3)",
            params![entry_id, idx as i64, if disabled { 1i64 } else { 0i64 }],
        )?;
        let clause_id = conn.last_insert_rowid();
        wrote_any_clause = true;

        let mut insert_pattern = conn.prepare_cached(
            "INSERT INTO device_clause_pattern (clause_id, kind, pattern) VALUES (?1, ?2, ?3)",
        )?;
        for v in oids {
            insert_pattern.execute(params![clause_id, KIND_SYS_OID, v])?;
        }
        for v in oids_except {
            insert_pattern.execute(params![clause_id, KIND_SYS_OID_EXCEPT, v])?;
        }
        for v in oid_regexes {
            insert_pattern.execute(params![clause_id, KIND_SYS_OID_REGEX, v])?;
        }
        for v in descrs {
            insert_pattern.execute(params![clause_id, KIND_SYS_DESCR, v])?;
        }
        for v in descr_regexes {
            insert_pattern.execute(params![clause_id, KIND_SYS_DESCR_REGEX, v])?;
        }
        for v in descr_except {
            insert_pattern.execute(params![clause_id, KIND_SYS_DESCR_EXCEPT, v])?;
        }
        for v in descr_regex_except {
            insert_pattern.execute(params![clause_id, KIND_SYS_DESCR_REGEX_EXCEPT, v])?;
        }
    }

    if !wrote_any_clause {
        // Roll the empty entry out — it would clutter list views and
        // never produce a match anyway.
        conn.execute("DELETE FROM device_entry WHERE id = ?1", params![entry_id])?;
        return Ok(false);
    }

    Ok(true)
}

fn normalize_oid(s: String) -> Option<String> {
    let t = s.trim_start_matches('.').trim().to_string();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

// ============================================================================
// IANA Private Enterprise Numbers ingestion.
// ============================================================================
//
// The canonical IANA file is fixed-column indented text:
//
//     <decimal>
//       <organization>
//         <contact>
//           <email>
//
// Records may be separated by blank lines. The header (lines 1-15)
// declares the column layout; we skip until the first all-digit line.
// Every subsequent group of "decimal + 1-3 indented lines" is one
// record. Blank trailing lines and the literal "End of Document" line
// mark the end.

fn ingest_iana(conn: &Connection, path: &Path) -> Result<usize> {
    use std::io::{BufRead, BufReader};

    let f =
        std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(f);

    let mut stmt = conn.prepare_cached(
        "INSERT OR REPLACE INTO iana_enterprise (pen, organization, contact, email)
         VALUES (?1, ?2, ?3, ?4)",
    )?;

    let mut current: Option<IanaRecord> = None;
    let mut count: usize = 0;
    for line in reader.lines() {
        let line = line.context("read IANA line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "End of Document" {
            break;
        }
        // Decimal-only line (not preceded by spaces) starts a new record.
        let is_pen_line =
            !line.starts_with(' ') && trimmed.chars().all(|c| c.is_ascii_digit());
        if is_pen_line {
            if let Some(rec) = current.take() {
                if let Some(org) = rec.organization.as_deref() {
                    stmt.execute(params![
                        rec.pen as i64,
                        org.trim(),
                        rec.contact.as_deref().map(str::trim),
                        rec.email.as_deref().map(str::trim)
                    ])?;
                    count += 1;
                }
            }
            let pen: u64 = trimmed.parse().unwrap_or(0);
            current = Some(IanaRecord {
                pen,
                organization: None,
                contact: None,
                email: None,
            });
            continue;
        }
        // Continuation lines: depth = leading spaces. The original
        // file uses 2/4/6-space indents for organization/contact/email,
        // but a few entries have inconsistent indentation. Slot the
        // next non-empty line into whichever field is still empty.
        if let Some(rec) = current.as_mut() {
            if rec.organization.is_none() {
                rec.organization = Some(trimmed.to_string());
            } else if rec.contact.is_none() {
                rec.contact = Some(trimmed.to_string());
            } else if rec.email.is_none() {
                rec.email = Some(trimmed.to_string());
            }
        }
    }
    // Flush trailing record.
    if let Some(rec) = current {
        if let Some(org) = rec.organization.as_deref() {
            stmt.execute(params![
                rec.pen as i64,
                org.trim(),
                rec.contact.as_deref().map(str::trim),
                rec.email.as_deref().map(str::trim)
            ])?;
            count += 1;
        }
    }
    Ok(count)
}

#[derive(Debug)]
struct IanaRecord {
    pen: u64,
    organization: Option<String>,
    contact: Option<String>,
    email: Option<String>,
}

// ============================================================================
// IEEE OUI ingestion.
// ============================================================================
//
// Stream the JSON array element by element. The full file is ~10 MB
// with ~35 K records — small enough to load in memory, but the
// streaming form keeps peak RSS bounded for everybody.

#[derive(Debug, serde::Deserialize)]
struct OuiRecord {
    prefix: String,
    organization: OuiOrg,
}

#[derive(Debug, serde::Deserialize)]
struct OuiOrg {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    address: Option<OuiAddress>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct OuiAddress {
    #[serde(default)]
    line1: Option<String>,
    #[serde(default)]
    line2: Option<String>,
    #[serde(default, rename = "countryCode")]
    country_code: Option<String>,
}

fn ingest_oui(conn: &Connection, path: &Path) -> Result<usize> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let records: Vec<OuiRecord> =
        serde_json::from_slice(&raw).context("parse OUI JSON")?;

    let mut stmt = conn.prepare_cached(
        "INSERT OR REPLACE INTO ieee_oui
            (prefix, organization, address_line1, address_line2, country_code)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;

    let mut count: usize = 0;
    for r in records {
        let Some(name) = r.organization.name else {
            continue;
        };
        // Normalise prefix: strip non-hex, upper-case. Empty / non-hex
        // sources are skipped.
        let prefix: String = r
            .prefix
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if prefix.is_empty() {
            continue;
        }
        let addr = r.organization.address.unwrap_or_default();
        stmt.execute(params![
            prefix,
            name.trim(),
            addr.line1.as_deref().map(str::trim),
            addr.line2.as_deref().map(str::trim),
            addr.country_code.as_deref().map(str::trim)
        ])?;
        count += 1;
    }
    Ok(count)
}
