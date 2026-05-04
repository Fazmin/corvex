//! `corvex-feed-harvest scaffold` — emit hand-authoring stubs.
//!
//! For each matching `.nasl` in the cache, write a JSON5 stub to
//! `rules-sources/openvas-port/_scaffolds/<oid>.json` carrying ONLY the
//! factual metadata extracted by `nasl::extract`. The author then:
//!   1. Reads the vendor advisory referenced in `provenance.advisory_urls`
//!      (NOT the NASL).
//!   2. Fills in `match_spec` with HTTP steps + matchers expressing the
//!      detection.
//!   3. Moves the file out of `_scaffolds/` into the appropriate family
//!      folder under `rules-sources/openvas-port/`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use walkdir::WalkDir;

use crate::nasl::{self, NaslMeta};

pub fn run(
    oids: &[String],
    families: &[String],
    limit: usize,
    cache: &Path,
    out: &Path,
    force: bool,
) -> Result<()> {
    if !cache.exists() {
        anyhow::bail!(
            "cache directory {} does not exist — run `corvex-feed-harvest sync` first",
            cache.display()
        );
    }
    std::fs::create_dir_all(out)
        .with_context(|| format!("create out dir {}", out.display()))?;

    let oid_filter: BTreeSet<String> = oids.iter().cloned().collect();
    let family_filter: Vec<String> = families
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let mut emitted = 0usize;
    let mut visited = 0usize;

    for entry in WalkDir::new(cache).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|e| e.to_str()) != Some("nasl") {
            continue;
        }
        visited += 1;

        let meta = match nasl::extract(entry.path()) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(target: "harvest", "skip {}: {}", entry.path().display(), e);
                continue;
            }
        };
        if !meta.looks_scaffoldable() {
            continue;
        }
        let oid = meta.oid.clone().unwrap_or_default();

        if !oid_filter.is_empty() && !oid_filter.contains(&oid) {
            continue;
        }
        if !family_filter.is_empty() {
            let fam = meta.family.clone().unwrap_or_default().to_lowercase();
            if !family_filter.iter().any(|f| fam.contains(f)) {
                continue;
            }
        }

        let dest = out.join(format!("{oid}.json"));
        if dest.exists() && !force {
            tracing::debug!(target: "harvest", "exists, skipping {}", dest.display());
            continue;
        }

        let stub = render_stub(&meta);
        let pretty = serde_json::to_string_pretty(&stub)
            .context("serialise scaffold stub")?;
        std::fs::write(&dest, format!("{pretty}\n"))
            .with_context(|| format!("write {}", dest.display()))?;
        emitted += 1;

        if oid_filter.is_empty() && emitted >= limit {
            break;
        }
    }

    println!(
        "[scaffold] visited {visited} .nasl files, emitted {emitted} stubs into {}",
        out.display()
    );
    if emitted == 0 && !oid_filter.is_empty() {
        anyhow::bail!("no matching OIDs found in {}", cache.display());
    }

    Ok(())
}

fn render_stub(meta: &NaslMeta) -> Value {
    let oid = meta.oid.clone().unwrap_or_default();
    let id = format!("openvas-{oid}");
    let name = meta.name.clone().unwrap_or_default();

    // Family → category guess. Authors override.
    let category = meta
        .family
        .as_ref()
        .map(|f| family_to_category(f))
        .unwrap_or_else(|| "info-disclosure".to_string());

    // Severity guess from category code. ACT_DENIAL = high, ACT_DESTRUCTIVE
    // = critical, the rest default to medium pending the human review.
    let severity = match meta.category.as_deref() {
        Some("ACT_DESTRUCTIVE_ATTACK") => "critical",
        Some("ACT_DENIAL") | Some("ACT_KILL_HOST") => "high",
        Some("ACT_GATHER_INFO") | Some("ACT_SETTINGS") => "info",
        _ => "medium",
    };

    let mut references: Vec<Value> = Vec::new();
    for cve in &meta.cves {
        references.push(Value::String(format!(
            "https://nvd.nist.gov/vuln/detail/{cve}"
        )));
    }
    for (name, value) in &meta.xrefs {
        if name.eq_ignore_ascii_case("URL") || value.starts_with("http") {
            references.push(Value::String(value.clone()));
        }
    }

    let mut provenance = Map::new();
    provenance.insert("openvas_oid".into(), Value::String(oid.clone()));
    if !meta.cves.is_empty() {
        provenance.insert(
            "cve".into(),
            Value::Array(meta.cves.iter().cloned().map(Value::String).collect()),
        );
    }
    if !meta.require_ports.is_empty() {
        provenance.insert(
            "default_ports".into(),
            Value::Array(
                meta.require_ports
                    .iter()
                    .map(|p| Value::Number((*p).into()))
                    .collect(),
            ),
        );
    }
    if !meta.cpe_match.is_empty() {
        provenance.insert(
            "cpe_match".into(),
            Value::Array(meta.cpe_match.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(fam) = &meta.family {
        provenance.insert("openvas_family".into(), Value::String(fam.clone()));
    }
    if let Some(cat) = &meta.category {
        provenance.insert("openvas_category".into(), Value::String(cat.clone()));
    }
    if !references.is_empty() {
        provenance.insert(
            "advisory_urls".into(),
            Value::Array(references.iter().take(3).cloned().collect()),
        );
    }

    json!({
        "$schema_note": "Scaffold stub — re-author `match_spec` against the vendor advisory in provenance.advisory_urls. Move out of _scaffolds/ when done.",
        "id": id,
        "name": name,
        "description": null,
        "severity": severity,
        "category": category,
        "owasp_2025": null,
        "cwe": null,
        "references": references,
        "match_spec": null,
        "provenance": Value::Object(provenance),
        "_TODO": [
            "Read vendor advisory in provenance.advisory_urls — NOT the NASL.",
            "Fill in `match_spec` with HTTP steps + status/body/header/cookie matchers.",
            "Set severity and category based on the advisory.",
            "Move this file out of _scaffolds/ into the appropriate family folder."
        ]
    })
}

fn family_to_category(family: &str) -> String {
    let f = family.to_lowercase();
    if f.contains("web server") || f.contains("http") {
        "service-exposure".into()
    } else if f.contains("cms") || f.contains("wordpress") || f.contains("joomla") {
        "cms".into()
    } else if f.contains("ssl") || f.contains("tls") {
        "tls-config".into()
    } else if f.contains("denial") {
        "dos".into()
    } else if f.contains("default") || f.contains("credentials") {
        "default-creds".into()
    } else if f.contains("sql") {
        "sqli".into()
    } else if f.contains("buffer") || f.contains("overflow") {
        "rce".into()
    } else {
        "info-disclosure".into()
    }
}

#[allow(dead_code)]
fn _unused() -> PathBuf {
    PathBuf::new()
}
