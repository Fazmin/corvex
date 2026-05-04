//! NASL **metadata** extractor.
//!
//! Pulls only factual identifiers (OID, CVE list, family, category,
//! default ports, CPE, BID, xref refs, dependencies, name). Does NOT
//! capture `description {}` body text, regex literals, helper-function
//! call sequences, or anything else that could carry creative expression.
//!
//! The extraction is line-based and lenient — NASL is whitespace-flexible
//! and we don't need a full parser. Each `script_*("...")` we care about
//! is matched with a per-key regex; the value is unescaped just enough
//! to drop NASL's `\` escapes.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use regex::Regex;

/// Everything we extract from a `.nasl` file. All fields are facts —
/// CVE IDs, OIDs, default ports, CPE URIs — none of which carry the
/// upstream's expressive choices.
#[derive(Debug, Default, Clone)]
pub struct NaslMeta {
    pub oid: Option<String>,
    pub name: Option<String>,
    pub family: Option<String>,
    pub category: Option<String>,
    pub cves: Vec<String>,
    pub bids: Vec<String>,
    pub xrefs: Vec<(String, String)>,
    pub require_ports: Vec<u16>,
    pub cpe_match: Vec<String>,
    pub dependencies: Vec<String>,
    pub cvss_base: Option<String>,
    pub source_path: Option<String>,
}

impl NaslMeta {
    /// True when the file looks substantive enough to scaffold from.
    /// Filters out feed includes, helper libraries, and stubs.
    pub fn looks_scaffoldable(&self) -> bool {
        self.oid.is_some() && self.name.is_some()
    }
}

/// Parse one `.nasl` file into `NaslMeta`. Reads the whole file (NASL
/// scripts are typically <50 KB) and pattern-matches the `script_*` calls
/// we care about. Anything we don't have a handler for is ignored — by
/// design.
pub fn extract(path: &Path) -> Result<NaslMeta> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;

    let mut meta = NaslMeta::default();
    meta.source_path = path.to_str().map(|s| s.to_string());

    if let Some(oid) = single_quoted_arg(&raw, "script_oid") {
        meta.oid = Some(oid);
    }
    if let Some(name) = single_quoted_arg(&raw, "script_name") {
        meta.name = Some(name);
    }
    if let Some(family) = single_quoted_arg(&raw, "script_family") {
        meta.family = Some(family);
    }
    if let Some(cat) = single_unquoted_arg(&raw, "script_category") {
        meta.category = Some(cat);
    }

    // CVEs and BIDs come through `script_cve_id("CVE-x", "CVE-y")` and
    // `script_bugtraq_id(123, 456)`. The extractor pulls every quoted /
    // numeric argument in those calls.
    meta.cves = list_quoted_args(&raw, "script_cve_id");
    meta.bids = list_numeric_args(&raw, "script_bugtraq_id");

    // `script_xref(name:"URL", value:"https://...")` — we keep these
    // because they are usually the vendor advisory URL, exactly what the
    // human re-author needs.
    meta.xrefs = list_xrefs(&raw);

    // `script_require_ports(80, 443, "Services/www")` — numeric and
    // service-string entries.
    meta.require_ports = list_ports(&raw);

    // `script_cpe_match("cpe:2.3:a:vendor:product:...")`. Some scripts use
    // a different macro; we pull anything that *looks* like a CPE in any
    // string-call position.
    meta.cpe_match = list_quoted_args(&raw, "script_cpe_match");
    if meta.cpe_match.is_empty() {
        meta.cpe_match = grep_cpe_uris(&raw);
    }

    meta.dependencies = list_quoted_args(&raw, "script_dependencies");
    meta.cvss_base = single_quoted_arg(&raw, "script_tag")
        .filter(|v| v.starts_with("cvss_base"));

    if meta.cves.iter().any(|c| c.is_empty()) {
        return Err(anyhow!("malformed CVE list in {}", path.display()));
    }

    Ok(meta)
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("static regex compiles")
}

/// Match `script_FOO("VALUE")` and return the unescaped VALUE.
fn single_quoted_arg(src: &str, name: &str) -> Option<String> {
    let pat = format!(r#"{}\s*\(\s*"((?:\\.|[^"\\])*)"\s*\)"#, regex::escape(name));
    let r = re(&pat);
    r.captures(src).map(|c| unescape_nasl(&c[1]))
}

/// Match `script_FOO(IDENT)` (no quotes) and return the identifier.
fn single_unquoted_arg(src: &str, name: &str) -> Option<String> {
    let pat = format!(r#"{}\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"#, regex::escape(name));
    let r = re(&pat);
    r.captures(src).map(|c| c[1].to_string())
}

/// Match all `script_FOO("a", "b", ...)` arguments and return the unescaped
/// quoted values. Repeated calls are concatenated.
fn list_quoted_args(src: &str, name: &str) -> Vec<String> {
    let outer = format!(r"{}\s*\(([^)]*)\)", regex::escape(name));
    let outer_re = re(&outer);
    let inner_re = re(r#""((?:\\.|[^"\\])*)""#);
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cap in outer_re.captures_iter(src) {
        let body = &cap[1];
        for m in inner_re.captures_iter(body) {
            let v = unescape_nasl(&m[1]);
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

fn list_numeric_args(src: &str, name: &str) -> Vec<String> {
    let outer = format!(r"{}\s*\(([^)]*)\)", regex::escape(name));
    let outer_re = re(&outer);
    let num_re = re(r"\b(\d+)\b");
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cap in outer_re.captures_iter(src) {
        for m in num_re.captures_iter(&cap[1]) {
            let v = m[1].to_string();
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

fn list_xrefs(src: &str) -> Vec<(String, String)> {
    // `script_xref(name:"X", value:"Y")`. Both kv pairs may appear in
    // either order; we extract the two quoted strings in encounter order.
    let r = re(
        r#"script_xref\s*\(\s*name\s*:\s*"((?:\\.|[^"\\])*)"\s*,\s*value\s*:\s*"((?:\\.|[^"\\])*)"\s*\)"#,
    );
    let r2 = re(
        r#"script_xref\s*\(\s*value\s*:\s*"((?:\\.|[^"\\])*)"\s*,\s*name\s*:\s*"((?:\\.|[^"\\])*)"\s*\)"#,
    );
    let mut out = Vec::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for cap in r.captures_iter(src) {
        let entry = (unescape_nasl(&cap[1]), unescape_nasl(&cap[2]));
        if seen.insert(entry.clone()) {
            out.push(entry);
        }
    }
    for cap in r2.captures_iter(src) {
        let entry = (unescape_nasl(&cap[2]), unescape_nasl(&cap[1]));
        if seen.insert(entry.clone()) {
            out.push(entry);
        }
    }
    out
}

fn list_ports(src: &str) -> Vec<u16> {
    let outer = re(r"script_require_ports\s*\(([^)]*)\)");
    let num_re = re(r"\b(\d{1,5})\b");
    let mut out: Vec<u16> = Vec::new();
    let mut seen: BTreeSet<u16> = BTreeSet::new();
    for cap in outer.captures_iter(src) {
        for m in num_re.captures_iter(&cap[1]) {
            if let Ok(p) = m[1].parse::<u16>() {
                if p > 0 && seen.insert(p) {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn grep_cpe_uris(src: &str) -> Vec<String> {
    let r = re(r#""(cpe:2\.3:[^"]+)""#);
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cap in r.captures_iter(src) {
        let v = cap[1].to_string();
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

fn unescape_nasl(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulls_oid_name_family_cves() {
        let src = r#"
            script_oid("1.3.6.1.4.1.25623.1.0.10394");
            script_name("Sample Apache check");
            script_family("Web Servers");
            script_category(ACT_GATHER_INFO);
            script_cve_id("CVE-2024-0001", "CVE-2024-0002");
            script_bugtraq_id(99999);
            script_require_ports("Services/www", 80, 443);
            script_xref(name:"URL", value:"https://example.com/advisory");
            script_cpe_match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*");
        "#;
        let p = std::env::temp_dir().join("corvex-feed-harvest-nasl-test.nasl");
        std::fs::write(&p, src).unwrap();
        let m = extract(&p).unwrap();
        assert_eq!(m.oid.as_deref(), Some("1.3.6.1.4.1.25623.1.0.10394"));
        assert_eq!(m.name.as_deref(), Some("Sample Apache check"));
        assert_eq!(m.family.as_deref(), Some("Web Servers"));
        assert_eq!(m.category.as_deref(), Some("ACT_GATHER_INFO"));
        assert_eq!(m.cves, vec!["CVE-2024-0001", "CVE-2024-0002"]);
        assert_eq!(m.bids, vec!["99999"]);
        assert_eq!(m.require_ports, vec![80, 443]);
        assert_eq!(
            m.xrefs,
            vec![("URL".to_string(), "https://example.com/advisory".to_string())]
        );
        assert_eq!(
            m.cpe_match,
            vec!["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"]
        );
        let _ = std::fs::remove_file(&p);
    }
}
