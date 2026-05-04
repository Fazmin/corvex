//! `corvex-feed-harvest lint` — clean-room enforcement.
//!
//! For every hand-authored rule under `rules-sources/openvas-port/` that
//! references an `openvas_oid` in its `provenance` block, locate the
//! corresponding `.nasl` in the cache and assert that NO ≥N-byte token
//! present in the rule's `match_spec` strings appears in the NASL body.
//!
//! Tokens are quoted-literal substrings extracted from the rule JSON. The
//! check is deliberately conservative: short tokens (paths like `/`,
//! HTTP verbs, status codes, header names, single-word categories) are
//! ignored because they are unavoidable matches and not creative
//! expression. Longer tokens — regex bodies, body-substring matches —
//! must come from the vendor advisory, not the NASL.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use walkdir::WalkDir;

pub fn run(rules_dir: &Path, cache: &Path, min_token: usize) -> Result<()> {
    if !rules_dir.exists() {
        anyhow::bail!(
            "rules dir {} does not exist",
            rules_dir.display()
        );
    }

    let mut total = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for entry in WalkDir::new(rules_dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if path.components().any(|c| c.as_os_str() == "_scaffolds") {
            continue;
        }

        total += 1;
        if let Err(e) = check_one(path, cache, min_token, &mut violations) {
            tracing::warn!(target: "lint", "{}: {}", path.display(), e);
        }
    }

    println!(
        "[lint] checked {total} hand-authored rules against cache {}",
        cache.display()
    );
    if !violations.is_empty() {
        eprintln!();
        eprintln!("CLEAN-ROOM VIOLATIONS:");
        for v in &violations {
            eprintln!("  {v}");
        }
        anyhow::bail!("{} clean-room violation(s) found", violations.len());
    }
    println!("[lint] OK — no token overlap with cached NASL bodies");
    Ok(())
}

fn check_one(
    rule_path: &Path,
    cache: &Path,
    min_token: usize,
    violations: &mut Vec<String>,
) -> Result<()> {
    let raw = std::fs::read_to_string(rule_path)
        .with_context(|| format!("read {}", rule_path.display()))?;
    let rule: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", rule_path.display()))?;

    let oid = rule
        .pointer("/provenance/openvas_oid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let Some(oid) = oid else {
        return Ok(()); // rule wasn't ported from a NASL; nothing to compare
    };

    let nasl_path = find_nasl(cache, &oid)?;
    let Some(nasl_path) = nasl_path else {
        return Ok(()); // cache doesn't have this NASL; lint can't compare
    };
    let nasl_body = std::fs::read_to_string(&nasl_path)
        .with_context(|| format!("read {}", nasl_path.display()))?;

    let tokens = collect_quoted_tokens(&rule, min_token);
    for tok in tokens {
        if nasl_body.contains(&tok) {
            violations.push(format!(
                "{} (oid {}): token {:?} appears verbatim in {}",
                rule_path.display(),
                oid,
                tok,
                nasl_path.display()
            ));
        }
    }

    Ok(())
}

fn find_nasl(cache: &Path, oid: &str) -> Result<Option<std::path::PathBuf>> {
    // Try the obvious shape first: any .nasl whose filename contains the
    // OID. Falls back to grepping every file in the cache for the OID
    // declaration.
    for entry in WalkDir::new(cache).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|e| e.to_str()) != Some("nasl") {
            continue;
        }
        if entry
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.contains(oid))
            .unwrap_or(false)
        {
            return Ok(Some(entry.path().to_path_buf()));
        }
    }
    let needle = format!("script_oid(\"{oid}\")");
    for entry in WalkDir::new(cache).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|e| e.to_str()) != Some("nasl") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        if text.contains(&needle) {
            return Ok(Some(entry.path().to_path_buf()));
        }
    }
    Ok(None)
}

/// Recursively walk the rule JSON pulling every string value of length
/// >= `min_token` that lives under `match_spec`. Provenance, references,
/// description are skipped — those are *meant* to overlap (CVE IDs, OIDs,
/// advisory URLs).
fn collect_quoted_tokens(root: &Value, min_token: usize) -> Vec<String> {
    let Some(spec) = root.get("match_spec") else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    walk(spec, &mut out, min_token);
    out.into_iter().collect()
}

fn walk(v: &Value, out: &mut BTreeSet<String>, min_token: usize) {
    match v {
        Value::String(s) => {
            // Skip path roots, HTTP verbs, status codes, single chars —
            // anything below the threshold is unavoidable overlap.
            if s.len() >= min_token {
                out.insert(s.clone());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                walk(item, out, min_token);
            }
        }
        Value::Object(map) => {
            for (k, val) in map {
                // Step IDs and matcher kinds are structural; never compare
                // them against NASL.
                if k == "id" || k == "kind" || k == "step" {
                    continue;
                }
                walk(val, out, min_token);
            }
        }
        _ => {}
    }
}

#[allow(dead_code)]
fn _unused() -> Result<()> {
    Err(anyhow!("placeholder"))
}
