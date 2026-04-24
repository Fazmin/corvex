//! Passive subdomain sources.
//!
//! Each implementation queries a public dataset that already indexes
//! certificate-transparency logs or passive DNS snapshots — no
//! traffic ever touches the target. All three sources here are
//! keyless so they work out of the box; keyed premium sources
//! (Shodan, Censys, VirusTotal) can slot in later behind the same
//! trait without disturbing the runner.
//!
//! The trait deliberately returns a plain `Vec<String>` rather than
//! streaming — a few thousand rows from the largest source is still
//! a few hundred KB of host strings, and the runner deduplicates the
//! union across sources anyway.
//!
//! ```ignore
//! use corvex_core::recon::passive::{PassiveSource, CrtShSource};
//! let client = reqwest::Client::new();
//! let hosts = CrtShSource.enumerate("example.com", &client).await?;
//! ```

use async_trait::async_trait;
use serde_json::Value;

/// Uniform contract every passive source implements. Runner fans out
/// to every enabled source concurrently; one source failing is
/// tolerated — the partial union is still useful.
#[async_trait]
pub trait PassiveSource: Send + Sync {
    fn name(&self) -> &'static str;
    async fn enumerate(
        &self,
        domain: &str,
        client: &reqwest::Client,
    ) -> std::result::Result<Vec<String>, String>;
}

// ---------------------------------------------------------------------
// crt.sh — Certificate Transparency search via the comodo-operated
// mirror. Accepts a wildcard prefix and returns every cert whose
// `name_value` field contains the matched host. The canonical first
// source for hobby + professional recon.
// ---------------------------------------------------------------------

pub struct CrtShSource;

#[async_trait]
impl PassiveSource for CrtShSource {
    fn name(&self) -> &'static str {
        "crt.sh"
    }
    async fn enumerate(
        &self,
        domain: &str,
        client: &reqwest::Client,
    ) -> std::result::Result<Vec<String>, String> {
        let url = format!(
            "https://crt.sh/?q=%25.{}&output=json",
            urlencoding_encode(domain)
        );
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        let body = resp.text().await.map_err(|e| format!("body: {e}"))?;
        parse_crtsh_json(&body, domain)
    }
}

pub fn parse_crtsh_json(body: &str, domain: &str) -> std::result::Result<Vec<String>, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| format!("json: {e}"))?;
    let arr = value.as_array().ok_or("crt.sh: not an array")?;
    let mut out = std::collections::BTreeSet::new();
    for row in arr {
        let Some(nv) = row.get("name_value").and_then(|v| v.as_str()) else {
            continue;
        };
        for raw in nv.split('\n') {
            if let Some(host) = clean_host(raw, domain) {
                out.insert(host);
            }
        }
    }
    Ok(out.into_iter().collect())
}

// ---------------------------------------------------------------------
// AlienVault OTX — community passive DNS via the Open Threat
// Exchange. No key required for basic indicator queries.
// ---------------------------------------------------------------------

pub struct AlienVaultSource;

#[async_trait]
impl PassiveSource for AlienVaultSource {
    fn name(&self) -> &'static str {
        "AlienVault OTX"
    }
    async fn enumerate(
        &self,
        domain: &str,
        client: &reqwest::Client,
    ) -> std::result::Result<Vec<String>, String> {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
            urlencoding_encode(domain)
        );
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        let body = resp.text().await.map_err(|e| format!("body: {e}"))?;
        parse_alienvault_json(&body, domain)
    }
}

pub fn parse_alienvault_json(
    body: &str,
    domain: &str,
) -> std::result::Result<Vec<String>, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| format!("json: {e}"))?;
    let records = value
        .get("passive_dns")
        .and_then(|v| v.as_array())
        .ok_or("alienvault: missing passive_dns")?;
    let mut out = std::collections::BTreeSet::new();
    for row in records {
        if let Some(host) = row.get("hostname").and_then(|v| v.as_str()) {
            if let Some(cleaned) = clean_host(host, domain) {
                out.insert(cleaned);
            }
        }
    }
    Ok(out.into_iter().collect())
}

// ---------------------------------------------------------------------
// CertSpotter — another CT source with a different lookback window
// than crt.sh. Free tier hits an anonymous rate limit after a burst;
// the runner surfaces that as a per-source error string without
// aborting the whole run.
// ---------------------------------------------------------------------

pub struct CertSpotterSource;

#[async_trait]
impl PassiveSource for CertSpotterSource {
    fn name(&self) -> &'static str {
        "CertSpotter"
    }
    async fn enumerate(
        &self,
        domain: &str,
        client: &reqwest::Client,
    ) -> std::result::Result<Vec<String>, String> {
        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={}\
             &expand=dns_names&include_subdomains=true",
            urlencoding_encode(domain)
        );
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("request: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        let body = resp.text().await.map_err(|e| format!("body: {e}"))?;
        parse_certspotter_json(&body, domain)
    }
}

pub fn parse_certspotter_json(
    body: &str,
    domain: &str,
) -> std::result::Result<Vec<String>, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| format!("json: {e}"))?;
    let arr = value
        .as_array()
        .ok_or("certspotter: not an array")?;
    let mut out = std::collections::BTreeSet::new();
    for row in arr {
        let Some(names) = row.get("dns_names").and_then(|v| v.as_array()) else {
            continue;
        };
        for n in names {
            if let Some(s) = n.as_str() {
                if let Some(cleaned) = clean_host(s, domain) {
                    out.insert(cleaned);
                }
            }
        }
    }
    Ok(out.into_iter().collect())
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// Normalise a host string returned by a passive source:
///
/// - strip leading `*.` (CT logs often carry wildcard certs)
/// - lowercase
/// - drop anything that isn't actually inside the queried domain (CT
///   logs occasionally return unrelated SANs)
/// - reject plainly malformed entries (empty, spaces, control chars)
fn clean_host(raw: &str, domain: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let stripped = trimmed.strip_prefix("*.").unwrap_or(&trimmed);
    if stripped.is_empty() || stripped.contains(' ') {
        return None;
    }
    if stripped.chars().any(|c| c.is_control()) {
        return None;
    }
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if stripped == d || stripped.ends_with(&format!(".{d}")) {
        Some(stripped.to_string())
    } else {
        None
    }
}

/// Minimal RFC 3986 percent encoder for query values. Avoids pulling
/// the whole `url` crate just for this.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_crtsh_json() {
        let body = r#"[
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "other.unrelated.com"}
        ]"#;
        let hosts = parse_crtsh_json(body, "example.com").unwrap();
        assert!(hosts.contains(&"api.example.com".to_string()));
        assert!(hosts.contains(&"www.example.com".to_string()));
        assert!(hosts.contains(&"example.com".to_string())); // from *.
        assert!(!hosts.iter().any(|h| h.contains("unrelated")));
        // dedup
        assert_eq!(
            hosts.iter().filter(|h| *h == "api.example.com").count(),
            1
        );
    }

    #[test]
    fn parses_alienvault_json() {
        let body = r#"{
            "passive_dns": [
                {"hostname": "api.example.com"},
                {"hostname": "db.example.com"},
                {"hostname": "other.com"}
            ]
        }"#;
        let hosts = parse_alienvault_json(body, "example.com").unwrap();
        assert!(hosts.contains(&"api.example.com".to_string()));
        assert!(hosts.contains(&"db.example.com".to_string()));
        assert!(!hosts.iter().any(|h| h.contains("other.com")));
    }

    #[test]
    fn parses_certspotter_json() {
        let body = r#"[
            {"dns_names": ["api.example.com", "www.example.com"]},
            {"dns_names": ["*.example.com"]},
            {"dns_names": ["skip.elsewhere.test"]}
        ]"#;
        let hosts = parse_certspotter_json(body, "example.com").unwrap();
        assert!(hosts.contains(&"api.example.com".to_string()));
        assert!(hosts.contains(&"www.example.com".to_string()));
        assert!(!hosts.iter().any(|h| h.contains("elsewhere")));
    }

    #[test]
    fn rejects_malformed_crtsh() {
        assert!(parse_crtsh_json("not json", "x.com").is_err());
        assert!(parse_crtsh_json("{}", "x.com").is_err());
    }
}
