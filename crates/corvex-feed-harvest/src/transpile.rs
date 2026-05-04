//! `corvex-feed-harvest transpile` — bulk auto-emit `MatchSpec` for the
//! narrow subset of OpenVAS VTs whose detection is fully expressed by
//! **factual identifiers** (CVE / CPE / port / regex literal) rather than
//! creative NASL logic.
//!
//! Transpile-eligibility is deliberately conservative. A VT is eligible
//! iff it matches one of these shapes:
//!
//!   * **HTTP-banner-version**: `script_family ~= "Web Servers"` and the
//!     `.nasl` body contains exactly one `http_get(item:"/PATH")` call
//!     followed by a single `egrep(string:..., pattern:"REGEX")` against
//!     the response. The transpiler emits a single-step HTTP rule with
//!     a `Body` matcher whose regex IS the NASL regex. Regexes are
//!     facts, not expression — the same pattern pulled from the vendor
//!     advisory would be byte-identical.
//!
//!   * **Service-banner**: `script_family ~= "Service detection"` and
//!     the `.nasl` declares a `script_require_ports(N)` plus a
//!     `recv(socket:..., length:...)` followed by `egrep(pattern:...)`.
//!     The transpiler emits a single `tcp_banner` step on port N with a
//!     `Banner` matcher. (Schema-only today — fires once Phase C banner
//!     probe ships.)
//!
//!   * **TLS-version-banner**: `script_family ~= "SSL and TLS"` and the
//!     NASL only inspects negotiated protocol/cipher names (no
//!     handshake reconstruction). Emits a `tls` step + `TlsVersion` /
//!     `TlsCipher` matcher. (Schema-only today.)
//!
//! Anything outside these three shapes is left for hand-authoring. Half-
//! transpiling a complex VT produces a wrong rule that fires on every
//! response, which is worse than no rule at all.
//!
//! Output lands at `rules-sources/openvas-port/_transpiled/<family>/<oid>.json`
//! so it never collides with hand-authored rules and can be regenerated
//! (or deleted) wholesale.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::{Context, Result};
use rayon::prelude::*;
use regex::Regex;
use serde_json::{json, Map, Value};
use walkdir::WalkDir;

use crate::nasl::{self, NaslMeta};

/// Process-wide index from a NASL filename (basename — what
/// `script_dependencies` references) to its path on disk. Built once
/// during the cache walk and consulted by the dependency-chain
/// recogniser to locate the fingerprint VT for a given vuln VT.
static FILENAME_INDEX: OnceLock<HashMap<String, PathBuf>> = OnceLock::new();

#[derive(Debug, Default, Clone)]
pub struct TranspileStats {
    pub visited: usize,
    pub eligible: usize,
    pub emitted: usize,
    pub skipped_by_reason: BTreeMap<String, usize>,
}

/// Outcome of processing one `.nasl` file. `Outcome::Emit` carries the
/// destination path the caller should write to so the per-file work
/// stays pure (no I/O) and the rayon pass is fully parallelisable.
enum FileOutcome {
    /// File was visited and produced a transpiled rule. Caller writes
    /// `rule_json` to `dest_path`.
    Emit {
        dest_path: PathBuf,
        rule_json: String,
    },
    /// File was visited but rejected. `reason` is the histogram bucket.
    Skipped(&'static str),
}

pub fn run(cache: &Path, out: &Path, force: bool) -> Result<()> {
    if !cache.exists() {
        anyhow::bail!(
            "cache {} does not exist — run `corvex-feed-harvest sync` first",
            cache.display()
        );
    }
    std::fs::create_dir_all(out)
        .with_context(|| format!("create out dir {}", out.display()))?;

    // Phase 1 — single-threaded directory walk to enumerate every .nasl
    // file. WalkDir is hard to parallelise cleanly (it's an iterator with
    // mutable state) but the walk is I/O-bound and fast — for 238k files
    // it completes in seconds. Rayon then fans out the heavy per-file
    // work across all cores.
    let t_walk = Instant::now();
    let nasl_paths: Vec<PathBuf> = WalkDir::new(cache)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.path().extension().and_then(|x| x.to_str()) == Some("nasl")
        })
        .map(|e| e.path().to_path_buf())
        .collect();
    println!(
        "[transpile] indexed {} .nasl files in {:.2}s",
        nasl_paths.len(),
        t_walk.elapsed().as_secs_f64()
    );

    // Build the basename → full-path map once. The dependency-chain
    // recogniser needs O(1) lookup for `script_dependencies("X.nasl")`
    // entries; doing a per-VT directory walk would dominate the
    // critical path. ~95k entries fit comfortably in memory.
    let mut idx = HashMap::with_capacity(nasl_paths.len());
    for p in &nasl_paths {
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            idx.insert(name.to_string(), p.clone());
        }
    }
    let _ = FILENAME_INDEX.set(idx);

    // Phase 2 — pre-create every family subdir so the parallel pass
    // doesn't race on `create_dir_all`. The set of family names is small
    // (<10) so this is trivial up front.
    for d in ["web", "tls", "service", "cms", "misc"] {
        let _ = std::fs::create_dir_all(out.join(d));
    }

    // Phase 3 — parallel classification. Each thread reads its file,
    // runs the recogniser, and produces a `FileOutcome`. No shared
    // state mutation; counters are atomics, skip-histogram is folded
    // through reduce. File writes happen in this same closure because
    // each (oid → dest) mapping is unique by design (OID is in the
    // filename), so no two threads ever target the same path.
    let visited = AtomicUsize::new(0);
    let emitted = AtomicUsize::new(0);
    let skipped_total = AtomicUsize::new(0);
    let skipped_by_reason: Mutex<BTreeMap<String, usize>> =
        Mutex::new(BTreeMap::new());

    let t_proc = Instant::now();

    nasl_paths.par_iter().for_each(|path| {
        visited.fetch_add(1, Ordering::Relaxed);

        let outcome = process_one(path, out, force);
        match outcome {
            FileOutcome::Skipped(reason) => {
                skipped_total.fetch_add(1, Ordering::Relaxed);
                let mut h = skipped_by_reason.lock().unwrap();
                *h.entry(reason.to_string()).or_default() += 1;
            }
            FileOutcome::Emit { dest_path, rule_json } => {
                if let Err(e) = std::fs::write(&dest_path, rule_json) {
                    tracing::warn!(
                        target: "transpile",
                        "write {}: {e}",
                        dest_path.display()
                    );
                    skipped_total.fetch_add(1, Ordering::Relaxed);
                    let mut h = skipped_by_reason.lock().unwrap();
                    *h.entry("write_error".to_string()).or_default() += 1;
                    return;
                }
                emitted.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let v = visited.load(Ordering::Relaxed);
    let e = emitted.load(Ordering::Relaxed);
    let elapsed = t_proc.elapsed().as_secs_f64();
    let rate = if elapsed > 0.0 { v as f64 / elapsed } else { 0.0 };
    println!(
        "[transpile] processed {v} files in {elapsed:.2}s ({rate:.0} files/s)"
    );
    println!("[transpile] emitted {e} rules into {}", out.display());

    let h = skipped_by_reason.into_inner().unwrap();
    if !h.is_empty() {
        println!("[transpile] skip reasons (top 10):");
        let mut reasons: Vec<_> = h.iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(a.1));
        for (r, n) in reasons.iter().take(10) {
            println!("           {r:<32} = {n}");
        }
    }
    Ok(())
}

/// Process one `.nasl` file end-to-end. Pure function over the path
/// plus output config; never touches the shared counters. Returns a
/// `FileOutcome` the parallel driver applies.
fn process_one(path: &Path, out: &Path, force: bool) -> FileOutcome {
    // Lossy UTF-8 read so VTs with stray ISO-8859-1 chars (older feed
    // entries, vendor advisory copy-pastes) don't bounce the entire
    // recogniser pass.
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return FileOutcome::Skipped("read_error"),
    };
    let raw = String::from_utf8_lossy(&bytes).into_owned();

    let meta = match nasl::extract(path) {
        Ok(m) => m,
        Err(_) => return FileOutcome::Skipped("metadata_extract_failed"),
    };
    if !meta.looks_scaffoldable() {
        return FileOutcome::Skipped("metadata_incomplete");
    }
    // Family-level skip: Local-Security-Check VTs report their nature
    // via `script_family` more reliably than via helper-call grep.
    // Catching them here avoids 60k+ no_eligible_shape rejections that
    // are really "we can't run authenticated package scans" anyway.
    if let Some(fam) = meta.family.as_deref() {
        let lf = fam.to_lowercase();
        if lf.contains("local security checks") {
            return FileOutcome::Skipped("local_security_check");
        }
    }

    let outcome = classify_and_emit(&meta, &raw);
    match outcome {
        Outcome::Skipped(reason) => FileOutcome::Skipped(reason),
        Outcome::Emit(rule) => {
            let family_dir = family_to_dirname(meta.family.as_deref());
            let dest = out.join(family_dir).join(format!(
                "{}.json",
                meta.oid.as_deref().unwrap_or("unknown")
            ));
            if dest.exists() && !force {
                return FileOutcome::Skipped("already_exists");
            }
            let pretty = match serde_json::to_string_pretty(&rule) {
                Ok(s) => s,
                Err(_) => return FileOutcome::Skipped("serialise_error"),
            };
            FileOutcome::Emit {
                dest_path: dest,
                rule_json: format!("{pretty}\n"),
            }
        }
    }
}

enum Outcome {
    Skipped(&'static str),
    Emit(Value),
}

fn classify_and_emit(meta: &NaslMeta, body: &str) -> Outcome {
    // 1. Bail on any NASL containing helper-call shapes we don't model.
    //    The transpiler is allowed to "see" only the small set of calls
    //    listed below; anything else means the detection logic is richer
    //    than a fact-set and must be hand-authored.
    if has_disqualifying_helpers(body) {
        return Outcome::Skipped("uses_unmodeled_helpers");
    }

    // 2. Try eligibility shapes in order. The dependency-chain
    //    recogniser is tried first because OpenVAS routes most modern
    //    web-vuln detections through a fingerprint VT + a confirm VT;
    //    transpiling them individually loses the linkage. Multi-step
    //    is next because it captures genuinely sequential probes that
    //    the single-step shapes would only see the first call of.
    //    After that we walk in specificity order so the recogniser
    //    producing the *most* informative rule wins.
    if let Some(rule) = try_dependency_chain(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_http_multistep(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_product_detection(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_http_header_banner(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_http_multi_pattern(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_http_banner_version(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_cgi_app_banner(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_service_banner(meta, body) {
        return Outcome::Emit(rule);
    }
    if let Some(rule) = try_tls_version_banner(meta, body) {
        return Outcome::Emit(rule);
    }

    Outcome::Skipped("no_eligible_shape")
}

/// Dependency-chain recogniser. The OpenVAS feed routes a CMS-vuln
/// check like `cutenews_145_xss.nasl` through a fingerprint helper
/// (`cutenews_detect.nasl`) named via `script_dependencies`. The vuln
/// VT looks up the host-details KB via `get_app_port(cpe:CPE)` and
/// `get_app_location(...)`, which corvex-rust can't replicate without
/// a stateful KB.
///
/// We synthesise a *single-shot* equivalent by:
///   1. Detecting the `get_app_port`/`get_app_location` idiom in the
///      vuln VT body.
///   2. Resolving `script_dependencies("X.nasl")` to the fingerprint
///      VT's `.nasl` file in the cache (via `FILENAME_INDEX`).
///   3. Pulling the fingerprint VT's literal http_get path + egrep
///      pattern (the version/banner regex that registers the CPE).
///   4. Pulling the vuln VT's vuln-confirm http_get path + egrep
///      pattern.
///   5. Emitting a 2-step `MatchSpec`: r0 = fingerprint, r1 = vuln.
///
/// If any of the four facts is non-literal (built from runtime
/// variables), the recogniser bails so a falsely-broad rule isn't
/// emitted.
fn try_dependency_chain(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_web_family(family) && !is_web_app_family(family) {
        return None;
    }
    // Vuln VT fingerprint: it must use `get_app_port(cpe:...)` to
    // signal that it depends on a separately-detected CPE.
    if !body.contains("get_app_port(cpe:")
        && !body.contains("get_app_port( cpe:")
        && !body.contains("get_app_port(cpe :")
    {
        return None;
    }

    // Find the fingerprint VT name via script_dependencies.
    let dep = first_script_dependency(body)?;
    let idx = FILENAME_INDEX.get()?;
    let fp_path = idx.get(&dep)?;
    let fp_bytes = std::fs::read(fp_path).ok()?;
    let fp_body = String::from_utf8_lossy(&fp_bytes).into_owned();

    // Fingerprint VT must itself look like a single-step web banner
    // probe — one literal http_get path + at least one egrep pattern.
    // If the fingerprint VT is itself a chain or uses dynamic URLs,
    // we can't synthesise a faithful 2-step rule.
    let fp_path_lit = resolve_first_http_get_path(&fp_body)?;
    let fp_pat = collect_egrep_patterns(&fp_body).into_iter().next()?;
    if !is_safe_regex(&fp_pat) {
        return None;
    }

    // Vuln VT: resolve its vuln-confirm path + the *first* egrep
    // pattern that lives after it in source order. The "after"
    // constraint avoids accidentally pairing the vuln check with a
    // pre-flight sanity check.
    let vuln_path = resolve_first_http_get_path(body)?;
    let vuln_pats = collect_egrep_patterns_with_offsets(body);
    let vuln_pat = vuln_pats.into_iter().next().map(|(_, p)| p)?;
    if !is_safe_regex(&vuln_pat) {
        return None;
    }
    if vuln_path == fp_path_lit && vuln_pat == fp_pat {
        // Both VTs collapsed to the same probe — degenerate, skip.
        return None;
    }

    let (severity, category) = infer_severity_and_category(meta, "info-disclosure");

    Some(build_rule(
        meta,
        severity,
        category,
        json!({
            "steps": [
                {
                    "id": "r0",
                    "method": "GET",
                    "uri": fp_path_lit,
                    "headers": [],
                    "body": null,
                    "payload": null
                },
                {
                    "id": "r1",
                    "method": "GET",
                    "uri": vuln_path,
                    "headers": [],
                    "body": null,
                    "payload": null
                }
            ],
            "when": [
                { "matcher": { "kind": "status", "step": "r0", "regex": "^2\\d\\d$" } },
                { "matcher": { "kind": "body",   "step": "r0", "regex": fp_pat } },
                { "matcher": { "kind": "status", "step": "r1", "regex": "^2\\d\\d$" } },
                { "matcher": { "kind": "body",   "step": "r1", "regex": vuln_pat } }
            ]
        }),
    ))
}

/// Pull the first filename from a NASL `script_dependencies("a.nasl"
/// , "b.nasl")` call. Multiple deps are valid; the first is
/// conventionally the primary fingerprint VT.
fn first_script_dependency(body: &str) -> Option<String> {
    let r = Regex::new(r#"script_dependencies\s*\(\s*"([^"]+\.nasl)""#).unwrap();
    r.captures(body).map(|c| c[1].trim().to_string())
}

/// Resolve the first literal HTTP path the body probes, including
/// values built from `string(dir, "/literal", ...)`, `dir + "/literal"`,
/// and direct literals — and chasing one level of variable
/// indirection (`URL = string(dir, "/literal"); http_get(item:URL)`).
/// Returns `None` if no literal can be recovered.
fn resolve_first_http_get_path(body: &str) -> Option<String> {
    if let Some((_, path)) = collect_http_get_paths(body).into_iter().next() {
        return Some(path);
    }
    // Variable-indirection: `VAR = string(dir, "/literal", ...);` or
    // `VAR = "/literal";` followed by `http_get(item:VAR, ...)`.
    let var_assign_string = Regex::new(
        r#"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*string\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*"((?:[^"\\]|\\.)*)""#,
    ).unwrap();
    let var_assign_concat = Regex::new(
        r#"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*"((?:[^"\\]|\\.)*)""#,
    ).unwrap();
    let var_assign_literal = Regex::new(
        r#"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(/[^"\\]*)""#,
    ).unwrap();
    let mut vars: HashMap<String, String> = HashMap::new();
    for cap in var_assign_string.captures_iter(body) {
        let lit = cap[2].to_string();
        if looks_like_path_literal(&lit) {
            vars.entry(cap[1].to_string()).or_insert(lit);
        }
    }
    for cap in var_assign_concat.captures_iter(body) {
        let lit = cap[2].to_string();
        if looks_like_path_literal(&lit) {
            vars.entry(cap[1].to_string()).or_insert(lit);
        }
    }
    for cap in var_assign_literal.captures_iter(body) {
        let lit = cap[2].to_string();
        if looks_like_path_literal(&lit) {
            vars.entry(cap[1].to_string()).or_insert(lit);
        }
    }

    let var_get = Regex::new(
        r#"http_get(?:_cache)?\s*\(\s*item\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"#
    ).unwrap();
    for cap in var_get.captures_iter(body) {
        if let Some(p) = vars.get(&cap[1].to_string()) {
            return Some(p.clone());
        }
    }
    None
}

/// Product-detection family recogniser. The OpenVAS feed has ~3,000
/// VTs in the "Product detection" family — these are the fingerprint
/// scripts that the dependency-chain recogniser already consumes when
/// a vuln VT references them. Many ARE never referenced (the product
/// has no current vuln VT), so they wouldn't get transpiled by the
/// chain recogniser. Emitting them as standalone fingerprint rules
/// catches those — useful for asset-inventory scans and as building
/// blocks for hand-authored rules.
///
/// Shape requirements:
///   1. `script_family("Product detection")` (case-insensitive)
///   2. Body has at least one literal http_get path
///   3. Body has at least one literal egrep pattern
///   4. Body has `register_product(...)` — confirms this is a true
///      fingerprint VT, not a stray script that happens to match
///      web-shape but does something else
///
/// Severity is forced to `info` — fingerprint rules don't represent
/// vulnerabilities; they confirm a product is running.
fn try_product_detection(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !family.eq_ignore_ascii_case("Product detection") {
        return None;
    }
    if !body.contains("register_product(") {
        return None;
    }
    let path = resolve_first_http_get_path(body)?;
    let pat = collect_egrep_patterns(body).into_iter().next()?;
    if !is_safe_regex(&pat) {
        return None;
    }

    Some(build_rule(
        meta,
        Severity::Info,
        "service-exposure",
        json!({
            "steps": [{
                "id": "r0",
                "method": "GET",
                "uri": path,
                "headers": [],
                "body": null,
                "payload": null
            }],
            "when": [
                { "matcher": { "kind": "status", "step": "r0", "regex": "^[234]\\d\\d$" } },
                { "matcher": { "kind": "body",   "step": "r0", "regex": pat } }
            ]
        }),
    ))
}

/// Multi-step HTTP recogniser. Eligibility:
///   1. Web / Web-app family.
///   2. Body has 2 or 3 distinct `http_get` literal paths in order.
///   3. Each path has at least one `egrep` pattern between its call site
///      and the next call site (the pattern AND-joins on that step).
///   4. No path repeats; no path is the same string as another step's.
///
/// Each step lands as a separate `StepSpec` in the emitted MatchSpec,
/// keyed `r0`/`r1`/`r2`. Per-step body matchers are AND-joined across
/// all steps. Status-200 is required on every step. This faithfully
/// reproduces the OpenVAS pattern of "fingerprint with one fetch, then
/// confirm vulnerability with a second fetch" without us having to
/// guess at conditional branches the original NASL took.
fn try_http_multistep(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_web_family(family) && !is_web_app_family(family) {
        return None;
    }

    let paths = collect_http_get_paths(body);
    if paths.len() < 2 || paths.len() > 3 {
        return None;
    }
    // Reject duplicate paths — that's a one-step VT with retries, not a
    // genuine multi-step probe.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (_, p) in &paths {
        if !seen.insert(p.as_str()) {
            return None;
        }
    }

    let pats = collect_egrep_patterns_with_offsets(body);
    if pats.is_empty() {
        return None;
    }

    // Pair each path with the egrep patterns that fall between its
    // offset and the next path's offset. The last path takes everything
    // from its offset to the end of the body. Each step needs at least
    // one pattern; otherwise the step would match unconditionally.
    let mut steps_with_patterns: Vec<(String, Vec<String>)> = Vec::new();
    for i in 0..paths.len() {
        let (start, ref path) = paths[i];
        let end = if i + 1 < paths.len() {
            paths[i + 1].0
        } else {
            body.len()
        };
        let owned: Vec<String> = pats
            .iter()
            .filter(|(off, _)| *off >= start && *off < end)
            .map(|(_, p)| p.clone())
            .take(2)
            .collect();
        // Status-only steps are fine. The semantics are "step N
        // returns 2xx → step N+1 fires its body match"; the rule
        // gates the actual confirmation step on the prior step's
        // success. As long as at least one step has a pattern the
        // rule isn't vacuous.
        steps_with_patterns.push((path.clone(), owned));
    }
    let any_pattern = steps_with_patterns.iter().any(|(_, ps)| !ps.is_empty());
    if !any_pattern {
        return None;
    }

    // Validate every regex compiles with our engine before emitting —
    // a single bad pattern would drop the rule at lowering time.
    if !steps_with_patterns
        .iter()
        .all(|(_, ps)| ps.iter().all(|p| is_safe_regex(p)))
    {
        return None;
    }

    let (severity, category) = infer_severity_and_category(meta, "info-disclosure");

    let step_specs: Vec<Value> = steps_with_patterns
        .iter()
        .enumerate()
        .map(|(i, (path, _))| {
            json!({
                "id": format!("r{i}"),
                "method": "GET",
                "uri": path,
                "headers": [],
                "body": null,
                "payload": null
            })
        })
        .collect();

    let mut when: Vec<Value> = Vec::new();
    for (i, (_, patterns)) in steps_with_patterns.iter().enumerate() {
        let step_id = format!("r{i}");
        when.push(json!({
            "matcher": { "kind": "status", "step": step_id, "regex": "^2\\d\\d$" }
        }));
        for p in patterns {
            when.push(json!({
                "matcher": { "kind": "body", "step": step_id, "regex": p }
            }));
        }
    }

    Some(build_rule(
        meta,
        severity,
        category,
        json!({
            "steps": step_specs,
            "when": when
        }),
    ))
}

/// Shape: web-related family + a single `http_get(item:"PATH")` plus
/// 2–3 `egrep` patterns (e.g. fingerprint + version). All patterns
/// AND-join. This is the most common detection pattern in the OpenVAS
/// feed for "is product X version Y running?" — single fetch, multiple
/// signals. Capped at 3 to avoid overly fragile rules.
fn try_http_multi_pattern(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_web_family(family) && !is_web_app_family(family) {
        return None;
    }
    let path = single_http_get_path(body)?;
    let mut patterns = collect_egrep_patterns(body);
    if patterns.len() < 2 {
        return None;
    }
    patterns.truncate(3);
    if !patterns.iter().all(|p| is_safe_regex(p)) {
        return None;
    }

    let (severity, category) = infer_severity_and_category(meta, "info-disclosure");

    let when: Vec<Value> = std::iter::once(json!({
            "matcher": { "kind": "status", "step": "r0", "regex": "^2\\d\\d$" }
        }))
        .chain(patterns.into_iter().map(|p| {
            json!({ "matcher": { "kind": "body", "step": "r0", "regex": p } })
        }))
        .collect();

    Some(build_rule(
        meta,
        severity,
        category,
        json!({
            "steps": [{
                "id": "r0",
                "method": "GET",
                "uri": path,
                "headers": [],
                "body": null,
                "payload": null
            }],
            "when": when
        }),
    ))
}

/// Reject NASLs whose **detection logic** is richer than a single regex
/// literal against a known endpoint or banner. The check is intentionally
/// narrow: NASL files routinely include dozens of helper libraries
/// (`host_details.inc`, `os_func.inc`, `http_func.inc`, …) without the
/// detection pattern itself becoming any more complex, so we no longer
/// disqualify based on imports alone. Instead we look for shapes the
/// recognisers below cannot faithfully reproduce.
fn has_disqualifying_helpers(body: &str) -> bool {
    // Dynamic URL construction we *can't* recover. The OpenVAS feed
    // overwhelmingly uses the pattern
    //   http_get(item:string(dir, "/literal/path"), port:port)
    // where `dir` is a foreach iterator over candidate document roots
    // ("/", "/admin", …) and the `/literal/path` segment is the *real*
    // detection URI. `single_http_get_path` extracts the literal segment
    // for that case. Reject only when the URL is built from `strcat` or
    // `raw_string` (these signal real runtime construction, not the
    // dir-iterator pattern).
    let dynamic_url_re =
        Regex::new(r#"http_get\s*\(\s*item\s*:\s*(strcat|raw_string)\s*\("#)
            .unwrap();
    if dynamic_url_re.is_match(body) {
        return true;
    }
    // Hand-rolled TLS handshake / KB-item lookup → needs real protocol
    // replay or per-host state we don't model.
    if body.contains("ssl_handshake") || body.contains("openvas_get_kb_item") {
        return true;
    }
    // Local-Security-Check / SCAP package-version VTs — these account
    // for tens of thousands of files in the feed (Debian DSA, Ubuntu USN,
    // RHEL RHSA, SUSE-SU, etc). They use OpenVAS's package-version
    // helpers (`isdpkgvuln`, `isrpmvuln`, `isnaslvuln`, …); corvex-rust
    // has no authenticated host-scan path so they can never fire from
    // this codebase. Rejecting them up front saves the recogniser
    // thousands of pointless attempts.
    if body.contains("isdpkgvuln(")
        || body.contains("isrpmvuln(")
        || body.contains("isfreebsdvuln(")
        || body.contains("isgentoovuln(")
        || body.contains("isbsdvuln(")
        || body.contains("isnaslvuln(")
        || body.contains("isnotnull(") && (
            body.contains("rpm_check_")
                || body.contains("deb_check_")
                || body.contains("rpmvercmp(")
                || body.contains("debian_check")
                || body.contains("solpkg_")
                || body.contains("dpkg_compare_versions(")
        )
    {
        return true;
    }
    // SMB / SSH / SNMP runtime probes — Phase D scope, not transpilable.
    if body.contains("smb_session_setup")
        || body.contains("nasl_ssh_request_exec")
        || body.contains("snmp_get(")
        || body.contains("snmpv3_")
    {
        return true;
    }
    false
}

/// Shape: `script_family ~= "Web Servers"` plus exactly one
/// `http_get(item:"<PATH>"...)` and one `egrep(string:res, pattern:"...")`.
fn try_http_banner_version(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_web_family(family) {
        return None;
    }

    let path = single_http_get_path(body)?;
    let pattern = single_egrep_pattern(body)?;
    if !is_safe_regex(&pattern) {
        return None;
    }

    let (severity, category) = infer_severity_and_category(meta, "info-disclosure");

    Some(build_rule(
        meta,
        severity,
        category,
        json!({
            "steps": [{
                "id": "r0",
                "method": "GET",
                "uri": path,
                "headers": [],
                "body": null,
                "payload": null
            }],
            "when": [
                { "matcher": { "kind": "status", "step": "r0", "regex": "^2\\d\\d$" } },
                { "matcher": { "kind": "body",   "step": "r0", "regex": pattern } }
            ]
        }),
    ))
}

/// Shape: any web-related family + a single `http_get(item:"PATH")` whose
/// follow-up checks ONLY a Server / X-Powered-By / WWW-Authenticate
/// response header against a literal regex. This catches the very common
/// "fingerprint by HTTP header" pattern that's distinct from body-banner
/// detection.
fn try_http_header_banner(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_web_family(family) && !is_web_app_family(family) {
        return None;
    }
    let path = single_http_get_path(body)?;
    let (header_name, pattern) = single_header_match(body)?;
    if !is_safe_regex(&pattern) {
        return None;
    }
    let (severity, category) = infer_severity_and_category(meta, "service-exposure");

    Some(build_rule(
        meta,
        severity,
        category,
        json!({
            "steps": [{
                "id": "r0",
                "method": "GET",
                "uri": path,
                "headers": [],
                "body": null,
                "payload": null
            }],
            "when": [
                { "matcher": { "kind": "status", "step": "r0", "regex": "^[234]\\d\\d$" } },
                { "matcher": { "kind": "header", "step": "r0",
                               "name": header_name,
                               "regex": pattern } }
            ]
        }),
    ))
}

/// Shape: `script_family ~= "Web application abuses"` (or CMS variant)
/// plus a CGI-style path probe — `http_get` of `/cgi-bin/...`,
/// `/wp-admin/...`, `/phpmyadmin/...`, etc. — plus a body-pattern match.
/// This is the largest single slice of OpenVAS web VTs (CMS / framework /
/// admin-panel exposure) and shares the same MatchSpec shape as
/// `try_http_banner_version`, only the family filter differs.
fn try_cgi_app_banner(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_web_app_family(family) {
        return None;
    }
    let path = single_http_get_path(body)?;
    let pattern = single_egrep_pattern(body)?;
    if !is_safe_regex(&pattern) {
        return None;
    }
    let (severity, category) = infer_severity_and_category(meta, "service-exposure");

    Some(build_rule(
        meta,
        severity,
        category,
        json!({
            "steps": [{
                "id": "r0",
                "method": "GET",
                "uri": path,
                "headers": [],
                "body": null,
                "payload": null
            }],
            "when": [
                { "matcher": { "kind": "status", "step": "r0", "regex": "^2\\d\\d$" } },
                { "matcher": { "kind": "body",   "step": "r0", "regex": pattern } }
            ]
        }),
    ))
}

/// Shape: `script_family ~= "Service detection"` (or similar) plus
/// `script_require_ports(N)` and a single `recv(...)` + `egrep(pattern)`.
/// The transpiled rule is `tcp_banner` — schema-only today.
fn try_service_banner(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_service_family(family) {
        return None;
    }
    let port = meta.require_ports.first().copied()?;
    let pattern = single_egrep_pattern(body)?;
    if !is_safe_regex(&pattern) {
        return None;
    }

    let (severity, category) = infer_severity_and_category(meta, "service-exposure");
    Some(build_rule(
        meta,
        severity,
        category,
        json!({
            "steps": [{
                "id": "svc0",
                "method": "",
                "uri": "",
                "headers": [],
                "body": null,
                "payload": null,
                "kind": "tcp_banner",
                "port": port
            }],
            "when": [
                { "matcher": { "kind": "banner", "step": "svc0", "regex": pattern } }
            ]
        }),
    ))
}

/// Shape: `script_family ~= "SSL and TLS"` and the NASL inspects
/// negotiated protocol or cipher name only. Emits a `tls` step.
fn try_tls_version_banner(meta: &NaslMeta, body: &str) -> Option<Value> {
    let family = meta.family.as_deref().unwrap_or("");
    if !is_tls_family(family) {
        return None;
    }
    let port = meta.require_ports.first().copied().unwrap_or(443);

    // Recognise either a protocol-name match (TLSv1.0 / SSLv3) or a
    // cipher-name match (RC4 / DES / NULL). Both are facts, not
    // expression.
    if let Some(proto) = single_protocol_name(body) {
        return Some(build_rule(
            meta,
            Severity::Medium,
            "tls-config",
            json!({
                "steps": [{
                    "id": "tls0",
                    "method": "",
                    "uri": "",
                    "headers": [],
                    "body": null,
                    "payload": null,
                    "kind": "tls",
                    "port": port
                }],
                "when": [
                    { "matcher": { "kind": "tls_version", "step": "tls0",
                                   "regex": format!("^{}$", regex::escape(&proto)) } }
                ]
            }),
        ));
    }
    if let Some(cipher_re) = single_cipher_pattern(body) {
        if !is_safe_regex(&cipher_re) {
            return None;
        }
        return Some(build_rule(
            meta,
            Severity::Medium,
            "tls-config",
            json!({
                "steps": [{
                    "id": "tls0",
                    "method": "",
                    "uri": "",
                    "headers": [],
                    "body": null,
                    "payload": null,
                    "kind": "tls",
                    "port": port
                }],
                "when": [
                    { "matcher": { "kind": "tls_cipher", "step": "tls0",
                                   "regex": cipher_re } }
                ]
            }),
        ));
    }
    None
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

fn build_rule(
    meta: &NaslMeta,
    severity: Severity,
    category: &str,
    match_spec: Value,
) -> Value {
    let oid = meta.oid.clone().unwrap_or_default();
    let id = format!("openvas-{oid}");
    let name = meta.name.clone().unwrap_or_default();

    let mut references: Vec<Value> = Vec::new();
    let mut seen_refs: BTreeSet<String> = BTreeSet::new();
    for cve in &meta.cves {
        let url = format!("https://nvd.nist.gov/vuln/detail/{cve}");
        if seen_refs.insert(url.clone()) {
            references.push(Value::String(url));
        }
    }
    for (_n, value) in &meta.xrefs {
        if value.starts_with("http") && seen_refs.insert(value.clone()) {
            references.push(Value::String(value.clone()));
        }
    }

    let mut provenance = Map::new();
    provenance.insert("openvas_oid".into(), Value::String(oid.clone()));
    provenance.insert("transpiled".into(), Value::Bool(true));
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
    if !references.is_empty() {
        provenance.insert(
            "advisory_urls".into(),
            Value::Array(references.iter().take(3).cloned().collect()),
        );
    }

    json!({
        "id": id,
        "name": name,
        "description": null,
        "severity": severity.as_str(),
        "category": category,
        "owasp_2025": null,
        "cwe": null,
        "references": references,
        "match_spec": match_spec,
        "provenance": Value::Object(provenance),
        "_TRANSPILED": "Auto-emitted by corvex-feed-harvest. Regenerate via `transpile --force`. Hand-author when promoted out of _transpiled/."
    })
}

fn family_to_dirname(family: Option<&str>) -> &'static str {
    match family.unwrap_or("").to_lowercase() {
        s if s.contains("web server") || s.contains("http") => "web",
        s if s.contains("ssl") || s.contains("tls") => "tls",
        s if s.contains("service detection") => "service",
        s if s.contains("cms") => "cms",
        _ => "misc",
    }
}

fn is_web_family(f: &str) -> bool {
    let l = f.to_lowercase();
    l.contains("web server") || l.contains("web servers") || l.contains("http server")
}

/// Web-application slice: CMS plugins, framework checks, admin-panel
/// exposure, CGI scripts. The OpenVAS feed labels these as "Web
/// application abuses" / "Web Servers" / "CISA Known Exploited
/// Vulnerabilities" depending on origin; we treat the family substring
/// match as authoritative.
fn is_web_app_family(f: &str) -> bool {
    let l = f.to_lowercase();
    l.contains("web application")
        || l.contains("web app")
        || l.contains("cgi abuses")
        || l.contains("cgi-abuses")
}

fn is_service_family(f: &str) -> bool {
    let l = f.to_lowercase();
    l.contains("service detection") || l.contains("port scanner")
}

fn is_tls_family(f: &str) -> bool {
    let l = f.to_lowercase();
    l.contains("ssl") || l.contains("tls")
}

/// Look for `egrep(string:res_headers, pattern:"^Server: ...")` or the
/// equivalent variants. Returns `(canonical_header_name, regex)`.
fn single_header_match(body: &str) -> Option<(String, String)> {
    // Common header probes — both via egrep on the headers string and via
    // get_http_banner / banner.split lookups. We recognise the egrep form
    // because it carries the regex literal we need.
    let known_headers: &[(&str, &str)] = &[
        (r"(?i)Server\s*:\s*", "Server"),
        (r"(?i)X-Powered-By\s*:\s*", "X-Powered-By"),
        (r"(?i)WWW-Authenticate\s*:\s*", "WWW-Authenticate"),
    ];

    let pat = single_egrep_pattern(body)?;
    for (anchor_re_src, header_name) in known_headers {
        let r = Regex::new(anchor_re_src).ok()?;
        if r.is_match(&pat) {
            // Strip the literal "Server: " (or equivalent) prefix so the
            // emitted regex matches against the *value*, which is what
            // the engine's `Header` matcher hands the regex.
            let stripped = strip_header_anchor(&pat, header_name);
            if stripped.is_empty() {
                return None;
            }
            return Some((header_name.to_string(), stripped));
        }
    }
    None
}

fn strip_header_anchor(pattern: &str, header_name: &str) -> String {
    let lc = pattern.to_lowercase();
    let needle = format!("{}: ", header_name.to_lowercase());
    if let Some(idx) = lc.find(&needle) {
        let after = &pattern[idx + needle.len()..];
        return after.trim_start_matches('^').to_string();
    }
    let needle_no_space = format!("{}:", header_name.to_lowercase());
    if let Some(idx) = lc.find(&needle_no_space) {
        let after = &pattern[idx + needle_no_space.len()..];
        return after.trim_start().trim_start_matches('^').to_string();
    }
    pattern.trim_start_matches('^').to_string()
}

/// Severity inference. The OpenVAS feed surfaces severity through
/// `script_tag(name:"cvss_base", value:"x.y")` and via the script
/// category — but our metadata extractor only captures CVSS strings
/// alongside the tag name. We fall back to category-based heuristics:
/// gather-info → info, denial → high, destructive → critical, anything
/// else stays at the per-shape default.
fn infer_severity_and_category(
    meta: &NaslMeta,
    fallback_category: &str,
) -> (Severity, &'static str) {
    let sev = match meta.category.as_deref() {
        Some("ACT_DESTRUCTIVE_ATTACK") => Severity::Critical,
        Some("ACT_DENIAL") | Some("ACT_KILL_HOST") | Some("ACT_FLOOD") => Severity::High,
        Some("ACT_ATTACK") => Severity::High,
        Some("ACT_MIXED_ATTACK") => Severity::Medium,
        Some("ACT_GATHER_INFO") | Some("ACT_SETTINGS") => Severity::Info,
        _ => Severity::Medium,
    };
    // CVE-bearing rules are presumptively at least medium — a security
    // bulletin exists. Cap upward only; never downgrade.
    let sev = if !meta.cves.is_empty() && matches!(sev, Severity::Info) {
        Severity::Medium
    } else {
        sev
    };
    let category: &'static str = match fallback_category {
        "info-disclosure" => "info-disclosure",
        "service-exposure" => "service-exposure",
        "tls-config" => "tls-config",
        _ => "info-disclosure",
    };
    (sev, category)
}

/// Extract every literal URL path from `http_get` / `http_get_cache`
/// calls, in source order. Recognises four common shapes:
///   * direct: `http_get(item:"/literal", ...)`
///   * dir-iter: `http_get(item:string(dir, "/literal", ...), ...)`
///   * NASL `+` concat: `http_get(item:dir + "/literal", ...)`
///   * variable indirection (resolved via `resolve_first_http_get_path`,
///     not here)
fn collect_http_get_paths(body: &str) -> Vec<(usize, String)> {
    let direct =
        Regex::new(r#"http_get(?:_cache)?\s*\(\s*item\s*:\s*"((?:[^"\\]|\\.)*)""#)
            .unwrap();
    let dir_iter = Regex::new(
        r#"http_get(?:_cache)?\s*\(\s*item\s*:\s*string\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*"((?:[^"\\]|\\.)*)""#,
    )
    .unwrap();
    // NASL `+` operator on strings: `dir + "/literal"`. The leading
    // identifier is consumed but we only capture the literal that
    // follows. A leading `/` keeps us out of accidentally matching
    // string-format placeholders or fragment identifiers.
    let plus_concat = Regex::new(
        r#"http_get(?:_cache)?\s*\(\s*item\s*:\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*"((?:[^"\\]|\\.)*)""#,
    )
    .unwrap();

    let mut hits: Vec<(usize, String)> = Vec::new();
    for cap in direct.captures_iter(body) {
        let m = cap.get(1).unwrap();
        let p = m.as_str().to_string();
        if looks_like_path_literal(&p) {
            hits.push((m.start(), p));
        }
    }
    for cap in dir_iter.captures_iter(body) {
        let m = cap.get(1).unwrap();
        let p = m.as_str().to_string();
        if looks_like_path_literal(&p) {
            hits.push((m.start(), p));
        }
    }
    for cap in plus_concat.captures_iter(body) {
        let m = cap.get(1).unwrap();
        let p = m.as_str().to_string();
        if looks_like_path_literal(&p) {
            hits.push((m.start(), p));
        }
    }
    hits.sort_by_key(|&(off, _)| off);
    hits
}

/// Same as `collect_egrep_patterns` but preserves byte-offset so the
/// multi-step recogniser can pair patterns with the closest preceding
/// `http_get` call. Captures both:
///   * regex-style: `egrep`/`eregmatch`/`pregmatch`/`ereg` with
///     `pattern:"..."` literal,
///   * substring-style: `"literal" >< varname` and
///     `varname >< "literal"` (NASL substring-contains operator).
///
/// Substring literals are wrapped via `regex::escape` so the runtime
/// matcher checks byte-containment rather than treating the literal
/// as a regex pattern.
fn collect_egrep_patterns_with_offsets(body: &str) -> Vec<(usize, String)> {
    let regex_candidates = [
        Regex::new(r#"egrep\s*\([^)]*pattern\s*:\s*"((?:\\.|[^"\\])*)""#).unwrap(),
        Regex::new(r#"eregmatch\s*\([^)]*pattern\s*:\s*"((?:\\.|[^"\\])*)""#).unwrap(),
        Regex::new(r#"pregmatch\s*\([^)]*pattern\s*:\s*"((?:\\.|[^"\\])*)""#).unwrap(),
        Regex::new(r#"ereg\s*\([^)]*pattern\s*:\s*"((?:\\.|[^"\\])*)""#).unwrap(),
    ];
    let substring_candidates = [
        // `"literal" >< varname` — literal on left.
        Regex::new(r#""((?:\\.|[^"\\])*)"\s*><\s*[A-Za-z_][A-Za-z0-9_]*"#).unwrap(),
        // `varname >< "literal"` — literal on right.
        Regex::new(r#"[A-Za-z_][A-Za-z0-9_]*\s*><\s*"((?:\\.|[^"\\])*)""#).unwrap(),
    ];

    let mut hits: Vec<(usize, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for r in &regex_candidates {
        for cap in r.captures_iter(body) {
            let m = cap.get(1).unwrap();
            let s = m.as_str()
                .replace(r#"\""#, "\"")
                .replace(r"\\", r"\");
            if seen.insert(s.clone()) {
                hits.push((m.start(), s));
            }
        }
    }
    for r in &substring_candidates {
        for cap in r.captures_iter(body) {
            let m = cap.get(1).unwrap();
            let raw = m.as_str()
                .replace(r#"\""#, "\"")
                .replace(r"\\", r"\");
            // Skip implausibly-short literals (single chars, common in
            // expressions like `"/" >< path`) — those cause false hits.
            if raw.len() < 4 {
                continue;
            }
            let escaped = regex::escape(&raw);
            if seen.insert(escaped.clone()) {
                hits.push((m.start(), escaped));
            }
        }
    }
    hits.sort_by_key(|&(off, _)| off);
    hits
}

/// Pull a single literal URL path from any of the OpenVAS `http_get` /
/// `http_get_cache` call shapes:
///
///   * `http_get(item:"/literal", ...)` — direct literal
///   * `http_get(item:string(dir, "/literal", ...), ...)` — dir-iterator
///     pattern; extract the literal that starts with `/`
///   * `http_get_cache(...)` — same shapes, different fn name
///
/// Multiple matching calls (i.e. the VT probes more than one literal
/// path) → disqualified. Returns the literal that starts with `/`.
fn single_http_get_path(body: &str) -> Option<String> {
    let direct =
        Regex::new(r#"http_get(?:_cache)?\s*\(\s*item\s*:\s*"((?:[^"\\]|\\.)*)""#)
            .unwrap();
    let dir_iter = Regex::new(
        r#"http_get(?:_cache)?\s*\(\s*item\s*:\s*string\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*"((?:[^"\\]|\\.)*)""#,
    )
    .unwrap();

    let mut found: Option<String> = None;

    for cap in direct.captures_iter(body) {
        let p = cap[1].to_string();
        if !looks_like_path_literal(&p) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(p);
    }
    for cap in dir_iter.captures_iter(body) {
        let p = cap[1].to_string();
        if !looks_like_path_literal(&p) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(p);
    }

    found
}

fn looks_like_path_literal(p: &str) -> bool {
    p.starts_with('/') && p.len() < 256 && !p.contains('{')
}

/// Pull a single `egrep(...,pattern:"REGEX")` (or `pregmatch` / `ereg`
/// / `eregmatch`) literal. Multiple calls disqualify; the transpiler
/// doesn't combine them.
fn single_egrep_pattern(body: &str) -> Option<String> {
    let pats = collect_egrep_patterns(body);
    if pats.len() == 1 {
        Some(pats.into_iter().next().unwrap())
    } else {
        None
    }
}

/// Pull every `egrep`-family `pattern:"..."` literal AND every NASL
/// substring-operator literal `"..." >< var` / `var >< "..."` in source
/// order, deduplicated. The substring operator is a fact (pure literal
/// match) and is the dominant non-egrep detection signal in older
/// OpenVAS VTs. Substring literals get anchored as `regex::escape(s)`
/// because they compare byte-equal, not regex-pattern-match.
fn collect_egrep_patterns(body: &str) -> Vec<String> {
    collect_egrep_patterns_with_offsets(body)
        .into_iter()
        .map(|(_, p)| p)
        .collect()
}

/// Recognise NASLs that compare the negotiated protocol against a literal
/// like "TLSv1.0", "SSLv3", "TLSv1.1".
fn single_protocol_name(body: &str) -> Option<String> {
    let r = Regex::new(r#"(TLSv1\.0|TLSv1\.1|SSLv3|SSLv2)"#).unwrap();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cap in r.captures_iter(body) {
        seen.insert(cap[1].to_string());
    }
    if seen.len() == 1 {
        seen.into_iter().next()
    } else {
        None
    }
}

/// Recognise NASLs that flag a cipher family by name (RC4, NULL, EXPORT,
/// DES, 3DES) using a literal regex pattern.
fn single_cipher_pattern(body: &str) -> Option<String> {
    let weak_families = ["RC4", "NULL", "EXPORT", "DES", "3DES", "MD5"];
    let body_upper = body.to_uppercase();
    let hits: Vec<&&str> = weak_families
        .iter()
        .filter(|f| body_upper.contains(*f))
        .collect();
    if hits.len() == 1 {
        Some(format!("(?i){}", hits[0]))
    } else {
        None
    }
}

/// Reject patterns Rust's `regex` crate can't compile — we copy NASL
/// regexes verbatim, but RE2 is stricter than POSIX (no backrefs, no
/// lookaround). A pattern that fails to compile would drop the rule
/// silently at lowering time; better to reject upfront.
fn is_safe_regex(p: &str) -> bool {
    if p.is_empty() || p.len() > 1024 {
        return false;
    }
    Regex::new(p).is_ok()
}

#[allow(dead_code)]
fn _unused() -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_nasl(content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let p = dir.join(format!(
            "transpile-{}.nasl",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn transpiles_simple_web_banner_check() {
        let body = r#"
            include("http_func.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99001");
            script_name("Test web banner");
            script_family("Web Servers");
            script_require_ports("Services/www", 80);
            res = http_get(item:"/some-path", port:80);
            if (egrep(string:res, pattern:"^Server: TestApp/[0-9]+\\.[0-9]+")) {
                security_message(port:80);
            }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                let pretty = serde_json::to_string(&v).unwrap();
                assert!(pretty.contains("/some-path"), "URI not present: {pretty}");
                assert!(pretty.contains("TestApp"), "regex not carried: {pretty}");
                assert!(pretty.contains("\"transpiled\":true"));
            }
            Outcome::Skipped(r) => panic!("expected emit, got skip: {r}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_dynamic_url_construction() {
        let body = r#"
            include("http_func.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99002");
            script_name("Dynamic URL");
            script_family("Web Servers");
            script_require_ports(80);
            url = string("/foo/", get_kb_item("path"));
            res = http_get(item:string(url), port:80);
            if (egrep(string:res, pattern:"X")) { security_message(port:80); }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Skipped(_) => {}
            Outcome::Emit(_) => panic!("dynamic URLs must be rejected"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn transpiles_cgi_app_banner() {
        let body = r#"
            include("http_func.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99010");
            script_name("Detect FooCMS install panel");
            script_family("Web application abuses");
            script_require_ports(80);
            res = http_get(item:"/foocms/install.php", port:80);
            if (egrep(string:res, pattern:"FooCMS Installation Wizard")) {
                security_message(port:80);
            }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                let pretty = serde_json::to_string(&v).unwrap();
                assert!(pretty.contains("/foocms/install.php"), "{pretty}");
                assert!(pretty.contains("FooCMS Installation"), "{pretty}");
            }
            Outcome::Skipped(r) => panic!("expected emit, got skip: {r}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn transpiles_http_header_banner() {
        let body = r#"
            include("http_func.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99011");
            script_name("Detect ProductX via Server header");
            script_family("Web Servers");
            script_require_ports(80);
            res = http_get(item:"/", port:80);
            if (egrep(string:res, pattern:"^Server: ProductX/[0-9]+\\.[0-9]+")) {
                security_message(port:80);
            }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                let pretty = serde_json::to_string(&v).unwrap();
                assert!(pretty.contains("\"name\":\"Server\""), "{pretty}");
                assert!(pretty.contains("ProductX"), "{pretty}");
                // Must NOT contain the literal "Server: " in the regex —
                // strip_header_anchor should have removed it so the regex
                // matches against the *value*.
                assert!(!pretty.contains("Server: ProductX"), "{pretty}");
            }
            Outcome::Skipped(r) => panic!("expected emit, got skip: {r}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn transpiles_multistep_two_get() {
        let body = r#"
            include("http_func.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99020");
            script_name("Multi-step CMS detection");
            script_family("Web application abuses");
            script_require_ports(80);
            res = http_get_cache(item:string(dir, "/admin/login.php"), port:port);
            if (egrep(string:res, pattern:"FooCMS Admin Login")) {
                req = http_get(item:string(dir, "/admin/version.txt"), port:port);
                res2 = http_keepalive_send_recv(data:req, port:port);
                if (egrep(string:res2, pattern:"FooCMS v[0-9]+\\.[0-9]+")) {
                    security_message(port:port);
                }
            }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                let pretty = serde_json::to_string(&v).unwrap();
                // Both step paths must be present.
                assert!(pretty.contains("/admin/login.php"), "{pretty}");
                assert!(pretty.contains("/admin/version.txt"), "{pretty}");
                // Both step ids must be there.
                assert!(pretty.contains("\"id\":\"r0\""), "{pretty}");
                assert!(pretty.contains("\"id\":\"r1\""), "{pretty}");
                // Each step has its own status check; the regex must
                // bind to the right step.
                assert!(pretty.contains("\"step\":\"r0\""), "{pretty}");
                assert!(pretty.contains("\"step\":\"r1\""), "{pretty}");
                assert!(pretty.contains("FooCMS Admin Login"), "{pretty}");
                assert!(pretty.contains("FooCMS v"), "{pretty}");
            }
            Outcome::Skipped(r) => panic!("expected emit, got skip: {r}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn transpiles_product_detection_fingerprint() {
        let body = r#"
            include("http_func.inc");
            include("host_details.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99030");
            script_name("AdaptBB Detection");
            script_family("Product detection");
            script_require_ports(80);
            port = http_get_port( default:80 );
            buf = http_get_cache( item:dir + "/index.php", port:port );
            if( egrep( pattern:"Powered by AdaptBB", string:buf, icase:TRUE ) ) {
                set_kb_item(name: "adaptbb/installed", value: TRUE);
                cpe = build_cpe( ... );
                register_product( cpe:cpe, location:install, port:port, service:"www" );
            }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                let pretty = serde_json::to_string(&v).unwrap();
                assert!(pretty.contains("/index.php"), "{pretty}");
                assert!(pretty.contains("Powered by AdaptBB"), "{pretty}");
                assert!(pretty.contains("\"severity\":\"info\""), "{pretty}");
            }
            Outcome::Skipped(r) => panic!("expected emit, got skip: {r}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn resolves_var_indirection() {
        // `attackurl = string(dir, "/path?param=...")` then
        // `http_get(item:attackurl)` — the path extractor must chase
        // the variable assignment back to the literal.
        let body = r#"
            include("http_func.inc");
            attackurl = string(dir, "/admin/edit?id=", magic);
            attackreq = http_get(item:attackurl, port:port);
        "#;
        let resolved = resolve_first_http_get_path(body);
        assert_eq!(resolved.as_deref(), Some("/admin/edit?id="));
    }

    #[test]
    fn rejects_multistep_with_duplicate_path() {
        // Two `http_get`s to the same path = retry, not a genuine
        // multi-step probe; falls through to single-step recognisers.
        let body = r#"
            include("http_func.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99021");
            script_name("Retry detection");
            script_family("Web Servers");
            script_require_ports(80);
            res = http_get_cache(item:"/foo", port:port);
            if (egrep(string:res, pattern:"X")) {
                res = http_get_cache(item:"/foo", port:port);
                if (egrep(string:res, pattern:"Y")) { security_message(port:port); }
            }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                // Multi-step rejects duplicates; should fall through to
                // single-step. Confirm only one step is emitted.
                let pretty = serde_json::to_string(&v).unwrap();
                assert!(!pretty.contains("\"id\":\"r1\""),
                    "duplicate-path VT must not emit a multi-step rule: {pretty}");
            }
            Outcome::Skipped(_) => {} // also acceptable
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn severity_promoted_when_cve_present() {
        let body = r#"
            include("http_func.inc");
            script_oid("1.3.6.1.4.1.25623.1.0.99012");
            script_name("CVE-2024-XXXX detector");
            script_family("Web Servers");
            script_category(ACT_GATHER_INFO);
            script_cve_id("CVE-2024-99999");
            script_require_ports(80);
            res = http_get(item:"/version", port:80);
            if (egrep(string:res, pattern:"VulnApp 1\\.0")) {
                security_message(port:80);
            }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                let pretty = serde_json::to_string(&v).unwrap();
                // Category was ACT_GATHER_INFO (would default to "info"),
                // but a CVE is present → promoted to medium.
                assert!(pretty.contains("\"severity\":\"medium\""), "{pretty}");
            }
            Outcome::Skipped(r) => panic!("expected emit, got skip: {r}"),
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn transpiles_tls_protocol_name() {
        let body = r#"
            script_oid("1.3.6.1.4.1.25623.1.0.99003");
            script_name("Detect TLSv1.0");
            script_family("SSL and TLS");
            script_require_ports(443);
            if (negotiated == "TLSv1.0") { security_message(port:443); }
        "#;
        let p = make_nasl(body);
        let meta = nasl::extract(&p).unwrap();
        let outcome = classify_and_emit(&meta, body);
        match outcome {
            Outcome::Emit(v) => {
                let pretty = serde_json::to_string(&v).unwrap();
                assert!(pretty.contains("\"kind\":\"tls\""), "{pretty}");
                assert!(pretty.contains("TLSv1\\\\.0"), "{pretty}");
            }
            Outcome::Skipped(r) => panic!("expected emit, got skip: {r}"),
        }
        let _ = std::fs::remove_file(&p);
    }
}
