//! Stack fingerprinting built on the Wappalyzer schema.
//!
//! # Why Wappalyzer-schema
//!
//! The Wappalyzer technology database is the de-facto format for web
//! stack detection. Each technology entry maps its product name to
//! matchers against HTTP response `headers`, `cookies`, response
//! `html`, `<meta>` tags, URL paths and JavaScript globals. Bundling a
//! real-world dataset is a natural upgrade path once license review
//! is done.
//!
//! # What ships today
//!
//! A small hand-curated seed — [`SEED_FINGERPRINTS`] — written to the
//! same schema as the Wappalyzer community project. It covers the
//! highest-signal stacks (nginx/Apache/IIS, WordPress, ASP.NET,
//! Express, Laravel, Django, Flask, PHP, jQuery, Bootstrap) and is
//! enough to annotate traffic with useful tags while an upstream
//! dataset is wired in.
//!
//! # Adding the full upstream
//!
//! `crates/corvex-intel/data/wappalyzer/technologies/*.json` is the
//! intended location. A companion `data/LICENSE_NOTES.md` lists the
//! attribution + license terms for every upstream source. The engine
//! already accepts entries of any shape — swap in the real data and
//! every downstream Check picks it up without code changes.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::path::Path;

/// One technology entry — mirrors the Wappalyzer `technologies.json`
/// schema closely enough that an upstream drop lands without code.
/// Intentionally not `Deserialize` — the static-str fields match the
/// seed data exactly; a separate owned-string `LoadedFingerprint`
/// type will land with the upstream JSON loader.
#[derive(Debug, Clone)]
pub struct Fingerprint {
    /// Display name, e.g. "WordPress".
    pub name: &'static str,
    /// Human-readable category tag, e.g. "CMS" or "Web Server".
    pub category: &'static str,
    /// Regex-style header patterns keyed by header name. The value
    /// pattern is a Wappalyzer-style regex; `\\;version:\\1` extraction
    /// hints are stripped before compilation.
    pub headers: &'static [(&'static str, &'static str)],
    /// `cookie_name -> regex pattern` entries (pattern may be empty to
    /// match on presence only).
    pub cookies: &'static [(&'static str, &'static str)],
    /// Regex patterns to run against the response body (text bodies
    /// only).
    pub html: &'static [&'static str],
    /// `<meta name="x" content="y">` patterns, keyed by `name`.
    pub meta: &'static [(&'static str, &'static str)],
    /// Regex patterns to run against the request URL path.
    pub url: &'static [&'static str],
    /// Implied additional tech (e.g. WordPress implies PHP). Added to
    /// the detection result when this tech matches.
    pub implies: &'static [&'static str],
}

/// Output of a single detection. `version` is populated when the
/// matching regex captured it via a named group or the Wappalyzer
/// `\\;version:\\1` hint — today the engine exposes captures via a
/// `version` named group when supplied.
#[derive(Debug, Clone, Serialize)]
pub struct FingerprintMatch {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub evidence: String,
}

/// Seed data — small, high-signal, redistribution-safe. Swap in an
/// upstream-sourced dataset by dropping JSON files under
/// `data/wappalyzer/` and adding a loader (TODO in 3C).
pub static SEED_FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        name: "nginx",
        category: "Web Server",
        headers: &[("Server", r"(?i)^nginx(?:/(?P<version>[0-9.]+))?")],
        cookies: &[],
        html: &[],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "Apache HTTP Server",
        category: "Web Server",
        headers: &[("Server", r"(?i)^Apache(?:/(?P<version>[0-9.]+))?")],
        cookies: &[],
        html: &[],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "Microsoft IIS",
        category: "Web Server",
        headers: &[("Server", r"(?i)^Microsoft-IIS(?:/(?P<version>[0-9.]+))?")],
        cookies: &[],
        html: &[],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "Cloudflare",
        category: "CDN",
        headers: &[
            ("Server", r"(?i)^cloudflare"),
            ("CF-Ray", r"."),
        ],
        cookies: &[("__cfduid", ""), ("__cf_bm", "")],
        html: &[],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "PHP",
        category: "Programming Language",
        headers: &[("X-Powered-By", r"(?i)^PHP(?:/(?P<version>[0-9.]+))?")],
        cookies: &[("PHPSESSID", "")],
        html: &[],
        meta: &[],
        url: &[r"(?i)\.php(?:[?#]|$)"],
        implies: &[],
    },
    Fingerprint {
        name: "ASP.NET",
        category: "Web Framework",
        headers: &[
            ("X-AspNet-Version", r"(?P<version>[0-9.]+)"),
            ("X-Powered-By", r"(?i)^ASP\.NET"),
        ],
        cookies: &[("ASP.NET_SessionId", ""), (".ASPXAUTH", "")],
        html: &[],
        meta: &[],
        url: &[r"(?i)\.aspx?(?:[?#]|$)"],
        implies: &["Microsoft IIS"],
    },
    Fingerprint {
        name: "WordPress",
        category: "CMS",
        headers: &[],
        cookies: &[("wordpress_logged_in_", ""), ("wp-settings-", "")],
        html: &[r"(?i)<link[^>]+/wp-content/", r"(?i)<link[^>]+/wp-includes/"],
        meta: &[("generator", r"(?i)^WordPress(?: (?P<version>[0-9.]+))?")],
        url: &[r"(?i)/wp-admin/", r"(?i)/wp-content/"],
        implies: &["PHP"],
    },
    Fingerprint {
        name: "Drupal",
        category: "CMS",
        headers: &[("X-Generator", r"(?i)^Drupal(?: (?P<version>[0-9.]+))?")],
        cookies: &[("SESS", "")],
        html: &[],
        meta: &[("Generator", r"(?i)^Drupal(?: (?P<version>[0-9.]+))?")],
        url: &[],
        implies: &["PHP"],
    },
    Fingerprint {
        name: "Laravel",
        category: "Web Framework",
        headers: &[],
        cookies: &[("laravel_session", ""), ("XSRF-TOKEN", "")],
        html: &[],
        meta: &[],
        url: &[],
        implies: &["PHP"],
    },
    Fingerprint {
        name: "Django",
        category: "Web Framework",
        headers: &[],
        cookies: &[("csrftoken", ""), ("django_language", "")],
        html: &[],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "Flask",
        category: "Web Framework",
        headers: &[("Server", r"(?i)Werkzeug(?:/(?P<version>[0-9.]+))?")],
        cookies: &[],
        html: &[],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "Express",
        category: "Web Framework",
        headers: &[("X-Powered-By", r"(?i)^Express")],
        cookies: &[("connect.sid", "")],
        html: &[],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "Next.js",
        category: "Web Framework",
        headers: &[("X-Powered-By", r"(?i)^Next\.js(?:/(?P<version>[0-9.]+))?")],
        cookies: &[],
        html: &[r#"(?i)<script id="__NEXT_DATA__""#],
        meta: &[("next-head-count", ".")],
        url: &[r"/_next/"],
        implies: &[],
    },
    Fingerprint {
        name: "jQuery",
        category: "JavaScript Library",
        headers: &[],
        cookies: &[],
        html: &[r"(?i)jquery[\-.]?(?P<version>[0-9.]+)?\.(?:min\.)?js"],
        meta: &[],
        url: &[],
        implies: &[],
    },
    Fingerprint {
        name: "Bootstrap",
        category: "UI Framework",
        headers: &[],
        cookies: &[],
        html: &[r"(?i)bootstrap[\-.]?(?P<version>[0-9.]+)?\.(?:min\.)?(?:js|css)"],
        meta: &[],
        url: &[],
        implies: &[],
    },
];

/// Minimal inputs the detector needs. Plays nicely with the types the
/// checks already have on hand (Response, Request, URL path).
pub struct DetectionInput<'a> {
    pub headers: &'a [(&'a str, &'a str)],
    pub cookies: &'a [(&'a str, &'a str)],
    pub body: &'a str,
    pub url_path: &'a str,
}

/// Shared interface between the compile-time seed [`Fingerprint`] and
/// the runtime-loaded [`LoadedFingerprint`]. The detector operates on
/// this so the same engine works with either dataset without a copy.
pub trait FingerprintLike {
    fn name(&self) -> &str;
    fn category(&self) -> &str;
    fn headers(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_>;
    fn cookies(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_>;
    fn html(&self) -> Box<dyn Iterator<Item = &str> + '_>;
    fn meta(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_>;
    fn url(&self) -> Box<dyn Iterator<Item = &str> + '_>;
    fn implies(&self) -> Box<dyn Iterator<Item = &str> + '_>;
}

impl FingerprintLike for Fingerprint {
    fn name(&self) -> &str {
        self.name
    }
    fn category(&self) -> &str {
        self.category
    }
    fn headers(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        Box::new(self.headers.iter().map(|(k, v)| (*k, *v)))
    }
    fn cookies(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        Box::new(self.cookies.iter().map(|(k, v)| (*k, *v)))
    }
    fn html(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.html.iter().copied())
    }
    fn meta(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        Box::new(self.meta.iter().map(|(k, v)| (*k, *v)))
    }
    fn url(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.url.iter().copied())
    }
    fn implies(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.implies.iter().copied())
    }
}

/// Run the Wappalyzer-style matchers against the supplied exchange
/// primitives using the bundled seed. Emits a de-duplicated list of
/// detections with the best version evidence per technology.
pub fn detect_stack(input: &DetectionInput<'_>) -> Vec<FingerprintMatch> {
    detect_any(input, SEED_FINGERPRINTS.iter())
}

/// Back-compat wrapper kept so existing call sites don't churn.
pub fn detect_with(
    input: &DetectionInput<'_>,
    dataset: &[Fingerprint],
) -> Vec<FingerprintMatch> {
    detect_any(input, dataset.iter())
}

/// Generic detector. Any iterator over types that implement
/// [`FingerprintLike`] is accepted — the seed, a `&[LoadedFingerprint]`
/// loaded from disk, or a chained iterator across multiple datasets
/// (the default wiring chains the vendored upstream first, then the
/// seed as a fallback).
pub fn detect_any<'a, I, F>(input: &DetectionInput<'_>, dataset: I) -> Vec<FingerprintMatch>
where
    I: Iterator<Item = &'a F>,
    F: FingerprintLike + ?Sized + 'a,
{
    let mut out: HashMap<String, FingerprintMatch> = HashMap::new();

    for fp in dataset {
        if let Some(m) = match_one(fp, input) {
            let key = fp.name().to_string();
            let entry = out.entry(key).or_insert_with(|| m.clone());
            if entry.version.is_none() && m.version.is_some() {
                *entry = m;
            }
            let name = fp.name().to_string();
            for implied in fp.implies() {
                out.entry(implied.to_string())
                    .or_insert_with(|| FingerprintMatch {
                        name: implied.to_string(),
                        category: "Implied".into(),
                        version: None,
                        evidence: format!("implied by {name}"),
                    });
            }
        }
    }
    let mut result: Vec<FingerprintMatch> = out.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

fn match_one<F: FingerprintLike + ?Sized>(
    fp: &F,
    input: &DetectionInput<'_>,
) -> Option<FingerprintMatch> {
    // Header match.
    for (hname, pattern) in fp.headers() {
        for (hk, hv) in input.headers {
            if hk.eq_ignore_ascii_case(hname) {
                if let Some(m) = pattern_match(pattern, hv) {
                    return Some(with_version(fp, &m, format!("header {hname}: {hv}")));
                }
            }
        }
    }
    // Cookie name match (value regex optional).
    for (cname, pattern) in fp.cookies() {
        for (ck, cv) in input.cookies {
            if cookie_name_matches(cname, ck) {
                if pattern.is_empty() {
                    return Some(FingerprintMatch {
                        name: fp.name().to_string(),
                        category: fp.category().to_string(),
                        version: None,
                        evidence: format!("cookie {ck}"),
                    });
                }
                if let Some(m) = pattern_match(pattern, cv) {
                    return Some(with_version(fp, &m, format!("cookie {ck}={cv}")));
                }
            }
        }
    }
    if !input.body.is_empty() {
        for pattern in fp.html() {
            if let Some(m) = pattern_match(pattern, input.body) {
                return Some(with_version(fp, &m, format!("html {}", m.matched)));
            }
        }
    }
    for pattern in fp.url() {
        if let Some(m) = pattern_match(pattern, input.url_path) {
            return Some(with_version(fp, &m, format!("url {}", input.url_path)));
        }
    }
    for (meta_name, pattern) in fp.meta() {
        if let Some(content) = extract_meta(input.body, meta_name) {
            if let Some(m) = pattern_match(pattern, &content) {
                return Some(with_version(
                    fp,
                    &m,
                    format!("meta {meta_name}=\"{content}\""),
                ));
            }
        }
    }
    None
}

fn with_version<F: FingerprintLike + ?Sized>(
    fp: &F,
    m: &PatternHit,
    evidence: String,
) -> FingerprintMatch {
    FingerprintMatch {
        name: fp.name().to_string(),
        category: fp.category().to_string(),
        version: m.version.clone(),
        evidence,
    }
}

struct PatternHit {
    matched: String,
    version: Option<String>,
}

static REGEX_CACHE: Lazy<std::sync::Mutex<HashMap<String, Option<Regex>>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

fn pattern_match(pattern: &str, hay: &str) -> Option<PatternHit> {
    let compiled = {
        let mut cache = REGEX_CACHE.lock().ok()?;
        cache
            .entry(pattern.to_string())
            .or_insert_with(|| Regex::new(pattern).ok())
            .clone()?
    };
    let caps = compiled.captures(hay)?;
    let matched = caps.get(0)?.as_str().to_string();
    let version = caps.name("version").map(|m| m.as_str().to_string());
    Some(PatternHit { matched, version })
}

fn cookie_name_matches(needle: &str, actual: &str) -> bool {
    // Wappalyzer entries that end in `_` or `-` are prefix-matched so
    // "wp-settings-" catches "wp-settings-time-1". Everything else is
    // exact (case-insensitive).
    if needle.ends_with('_') || needle.ends_with('-') {
        return actual
            .to_ascii_lowercase()
            .starts_with(&needle.to_ascii_lowercase());
    }
    actual.eq_ignore_ascii_case(needle)
}

fn extract_meta(body: &str, name: &str) -> Option<String> {
    // Light hand-rolled parse — good enough for tag detection, not a
    // general-purpose HTML parser.
    let body_l = body.to_ascii_lowercase();
    let needle = format!(r#"name="{}""#, name.to_ascii_lowercase());
    let idx = body_l.find(&needle)?;
    let tail = &body[idx..];
    let end = tail.find('>').unwrap_or(tail.len());
    let head = &tail[..end];
    let c_idx = head.to_ascii_lowercase().find("content=")?;
    let value_start = c_idx + "content=".len();
    let rest = &head[value_start..];
    let rest = rest.trim_start_matches(['\'', '"']);
    let end_quote = rest.find(['\'', '"']).unwrap_or(rest.len());
    Some(rest[..end_quote].to_string())
}

// ============================================================================
// Wappalyzer upstream JSON loader
// ============================================================================

/// Runtime-loaded counterpart of [`Fingerprint`]. Populated from the
/// upstream Wappalyzer `technologies/*.json` dataset. Field layout
/// mirrors the static seed so code reading fingerprints can be
/// written once against the [`FingerprintLike`] trait.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LoadedFingerprint {
    pub name: String,
    pub category: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub html: Vec<String>,
    pub meta: Vec<(String, String)>,
    pub url: Vec<String>,
    pub implies: Vec<String>,
}

impl FingerprintLike for LoadedFingerprint {
    fn name(&self) -> &str {
        &self.name
    }
    fn category(&self) -> &str {
        &self.category
    }
    fn headers(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        Box::new(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }
    fn cookies(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        Box::new(self.cookies.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }
    fn html(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.html.iter().map(|s| s.as_str()))
    }
    fn meta(&self) -> Box<dyn Iterator<Item = (&str, &str)> + '_> {
        Box::new(self.meta.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }
    fn url(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.url.iter().map(|s| s.as_str()))
    }
    fn implies(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        Box::new(self.implies.iter().map(|s| s.as_str()))
    }
}

// The build script emits these constants from the vendored dataset.
// When the dataset is absent (e.g. fresh checkout before the refresh
// script runs) both come out empty and every caller falls back to
// [`SEED_FINGERPRINTS`].
include!(concat!(env!("OUT_DIR"), "/wappalyzer_embedded.rs"));

/// Compile-time-embedded Wappalyzer dataset. Parsed once on first
/// access and cached — the vendored data is stable for the lifetime
/// of the binary, so re-parsing on every call would be wasted work.
static EMBEDDED_DATASET: Lazy<Vec<LoadedFingerprint>> = Lazy::new(|| {
    let cats = EMBEDDED_CATEGORIES
        .map(parse_categories_json)
        .unwrap_or_default();
    let mut out = Vec::new();
    for (name, raw) in EMBEDDED_TECHNOLOGIES {
        if name.eq_ignore_ascii_case("categories.json") {
            continue;
        }
        ingest_technologies_json(raw, &cats, &mut out);
    }
    out
});

/// Return the vendored dataset baked into the binary at build time.
/// The slice is empty when the refresh script hasn't been run; call
/// sites should chain a fallback to [`SEED_FINGERPRINTS`].
pub fn embedded_dataset() -> &'static [LoadedFingerprint] {
    &EMBEDDED_DATASET
}

/// Back-compat path for loading a dataset off disk (tests, optional
/// user-supplied overrides). Production callers should prefer
/// [`embedded_dataset`] so the app works from any CWD.
pub fn load_dataset(dir: &Path) -> std::io::Result<Vec<LoadedFingerprint>> {
    let mut out = Vec::new();
    let mut categories: HashMap<i64, String> = HashMap::new();

    if !dir.exists() {
        return Ok(out);
    }

    let categories_path = dir.join("categories.json");
    if categories_path.exists() {
        let raw = std::fs::read_to_string(&categories_path)?;
        categories = parse_categories_json(&raw);
    }

    let tech_dir = dir.join("technologies");
    let roots = if tech_dir.exists() {
        vec![tech_dir]
    } else {
        vec![dir.to_path_buf()]
    };

    for root in roots {
        for entry in std::fs::read_dir(&root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.eq_ignore_ascii_case("categories.json"))
                .unwrap_or(false)
            {
                continue;
            }
            let raw = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            ingest_technologies_json(&raw, &categories, &mut out);
        }
    }
    Ok(out)
}

fn parse_categories_json(raw: &str) -> HashMap<i64, String> {
    let mut out = HashMap::new();
    let Ok(cats) = serde_json::from_str::<JsonValue>(raw) else {
        return out;
    };
    if let Some(obj) = cats.as_object() {
        for (id_str, value) in obj {
            if let (Ok(id), Some(name)) = (
                id_str.parse::<i64>(),
                value.get("name").and_then(|v| v.as_str()),
            ) {
                out.insert(id, name.to_string());
            }
        }
    }
    out
}

fn ingest_technologies_json(
    raw: &str,
    categories: &HashMap<i64, String>,
    out: &mut Vec<LoadedFingerprint>,
) {
    let parsed: JsonValue = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(target: "intel", "technologies parse failed: {e}");
            return;
        }
    };
    let Some(obj) = parsed.as_object() else {
        return;
    };
    for (name, def) in obj {
        if let Some(fp) = parse_wappalyzer_entry(name, def, categories) {
            out.push(fp);
        }
    }
}

fn parse_wappalyzer_entry(
    name: &str,
    def: &JsonValue,
    categories: &HashMap<i64, String>,
) -> Option<LoadedFingerprint> {
    let Some(obj) = def.as_object() else {
        return None;
    };

    let category = obj
        .get("cats")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_i64())
        .and_then(|id| categories.get(&id).cloned())
        .unwrap_or_else(|| "Unknown".to_string());

    let headers = parse_keyvals(obj.get("headers"));
    let cookies = parse_keyvals(obj.get("cookies"));
    let meta = parse_keyvals(obj.get("meta"));
    let html = parse_string_list(obj.get("html"));
    let url = parse_string_list(obj.get("url"));
    let implies = parse_string_list(obj.get("implies"))
        .into_iter()
        .map(strip_version_hints)
        .collect();

    Some(LoadedFingerprint {
        name: name.to_string(),
        category,
        headers: normalize_patterns(headers),
        cookies: normalize_patterns(cookies),
        meta: normalize_patterns(meta),
        html: html.into_iter().map(normalize_pattern).collect(),
        url: url.into_iter().map(normalize_pattern).collect(),
        implies,
    })
}

fn parse_keyvals(v: Option<&JsonValue>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(JsonValue::Object(map)) = v else {
        return out;
    };
    for (k, v) in map {
        match v {
            JsonValue::String(s) => out.push((k.clone(), s.clone())),
            JsonValue::Array(arr) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        out.push((k.clone(), s.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_string_list(v: Option<&JsonValue>) -> Vec<String> {
    match v {
        Some(JsonValue::String(s)) => vec![s.clone()],
        Some(JsonValue::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn normalize_patterns(entries: Vec<(String, String)>) -> Vec<(String, String)> {
    entries
        .into_iter()
        .map(|(k, v)| (k, normalize_pattern(v)))
        .collect()
}

/// Wappalyzer patterns carry metadata in `\\;` separators after the
/// regex: `name\\;version:\\1\\;confidence:50`. Strip the metadata and
/// rewrite the `\\1`-style version hint into a named capture Rust's
/// regex engine can use.
fn normalize_pattern(raw: String) -> String {
    let mut parts = raw.split("\\;");
    let regex_part = parts.next().unwrap_or("").to_string();
    let mut version_group: Option<u32> = None;
    for meta in parts {
        let meta = meta.trim();
        if let Some(rest) = meta.strip_prefix("version:\\") {
            if let Ok(n) = rest.trim().parse() {
                version_group = Some(n);
            }
        }
    }
    rewrite_capture_group(&regex_part, version_group)
}

fn strip_version_hints(raw: String) -> String {
    raw.split("\\;").next().unwrap_or("").to_string()
}

/// Convert the Nth unnamed capture group in `pattern` into a named
/// `version` group so [`match_one`] can extract it uniformly. If
/// `target` is `None`, return the pattern unchanged.
fn rewrite_capture_group(pattern: &str, target: Option<u32>) -> String {
    let Some(target) = target else {
        return pattern.to_string();
    };
    let mut out = String::with_capacity(pattern.len() + 16);
    let bytes = pattern.as_bytes();
    let mut i = 0;
    let mut group_index = 0u32;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            out.push(c as char);
            out.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if c == b'(' {
            // Non-capturing groups `(?:` and already-named `(?P<` don't count.
            let next_two = bytes.get(i + 1).copied();
            let is_non_capture = matches!(next_two, Some(b'?'));
            if is_non_capture {
                out.push('(');
                i += 1;
                continue;
            }
            group_index += 1;
            if group_index == target {
                out.push_str("(?P<version>");
                i += 1;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod loader_tests {
    use super::*;

    #[test]
    fn normalize_extracts_version_hint() {
        let got = normalize_pattern(r"nginx/([0-9.]+)\;version:\1".to_string());
        assert!(got.contains("(?P<version>"), "rewritten: {got}");
    }

    #[test]
    fn normalize_strips_metadata_without_version() {
        let got = normalize_pattern(r"ngx_pagespeed\;confidence:50".to_string());
        assert_eq!(got, "ngx_pagespeed");
    }

    #[test]
    fn loader_parses_minimal_entry() {
        let tmp = std::env::temp_dir().join(format!("cvx-wapp-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("technologies")).unwrap();
        std::fs::write(
            tmp.join("categories.json"),
            r#"{"22":{"name":"Web Server","priority":1}}"#,
        )
        .unwrap();
        std::fs::write(
            tmp.join("technologies").join("n.json"),
            r#"{
              "Nginx": {
                "cats": [22],
                "headers": { "Server": "nginx(?:/([0-9.]+))?\\;version:\\1" },
                "implies": ["Event Loop\\;confidence:50"]
              }
            }"#,
        )
        .unwrap();
        let loaded = load_dataset(&tmp).unwrap();
        assert_eq!(loaded.len(), 1);
        let fp = &loaded[0];
        assert_eq!(fp.name, "Nginx");
        assert_eq!(fp.category, "Web Server");
        assert!(fp.headers[0].1.contains("(?P<version>"));
        assert_eq!(fp.implies, vec!["Event Loop".to_string()]);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(
        headers: &'a [(&'a str, &'a str)],
        cookies: &'a [(&'a str, &'a str)],
        body: &'a str,
        url_path: &'a str,
    ) -> DetectionInput<'a> {
        DetectionInput {
            headers,
            cookies,
            body,
            url_path,
        }
    }

    #[test]
    fn nginx_with_version() {
        let hits = detect_stack(&input(&[("Server", "nginx/1.24.0")], &[], "", "/"));
        let n = hits.iter().find(|h| h.name == "nginx").unwrap();
        assert_eq!(n.version.as_deref(), Some("1.24.0"));
    }

    #[test]
    fn wordpress_implies_php() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>"#;
        let hits = detect_stack(&input(&[], &[], body, "/"));
        let names: Vec<_> = hits.iter().map(|h| h.name.clone()).collect();
        assert!(names.iter().any(|n| n == "WordPress"));
        assert!(names.iter().any(|n| n == "PHP"));
    }

    #[test]
    fn php_url_match() {
        let hits = detect_stack(&input(&[], &[], "", "/index.php?x=1"));
        assert!(hits.iter().any(|h| h.name == "PHP"));
    }

    #[test]
    fn cookie_prefix_match() {
        let hits = detect_stack(&input(
            &[],
            &[("wp-settings-time-1", "1234")],
            "",
            "/",
        ));
        assert!(hits.iter().any(|h| h.name == "WordPress"));
    }
}
