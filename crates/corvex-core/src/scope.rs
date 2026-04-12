//! Scope restriction for the crawler and active fuzzers.
//!
//! Controls which URLs the crawler is allowed to follow and which
//! targets the fuzzers are allowed to probe. Without scope, active
//! scanning would escape to third-party domains.

use regex::Regex;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// Only the exact target domain (e.g. `www.example.com`).
    Domain,
    /// The target domain + all subdomains (`*.example.com`).
    Subdomains,
    /// Only URLs under the target path prefix.
    Folder,
    /// Only the exact target URL — no crawling at all.
    Page,
}

impl ScopeKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "domain" => Some(Self::Domain),
            "subdomains" | "subdomain" => Some(Self::Subdomains),
            "folder" | "directory" => Some(Self::Folder),
            "page" | "url" => Some(Self::Page),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopeFilter {
    kind: ScopeKind,
    origin_host: String,
    origin_path: String,
    base_domain: String,
    excludes: Vec<Regex>,
}

impl ScopeFilter {
    pub fn new(kind: ScopeKind, seed_url: &str, excludes: Vec<Regex>) -> Self {
        let parsed = Url::parse(seed_url).unwrap_or_else(|_| {
            Url::parse(&format!("http://{seed_url}")).expect("valid seed URL")
        });
        let origin_host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let origin_path = parsed.path().to_string();
        let base_domain = extract_base_domain(&origin_host);
        Self {
            kind,
            origin_host,
            origin_path,
            base_domain,
            excludes,
        }
    }

    /// Returns `true` if `url` is within scope.
    pub fn allows(&self, url: &str) -> bool {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();

        // Exclude patterns checked first — they override everything.
        for rx in &self.excludes {
            if rx.is_match(url) {
                return false;
            }
        }

        match self.kind {
            ScopeKind::Domain => host == self.origin_host,
            ScopeKind::Subdomains => {
                host == self.origin_host
                    || host.ends_with(&format!(".{}", self.base_domain))
                    || host == self.base_domain
            }
            ScopeKind::Folder => {
                host == self.origin_host && parsed.path().starts_with(&self.origin_path)
            }
            ScopeKind::Page => {
                host == self.origin_host && parsed.path() == self.origin_path
            }
        }
    }
}

fn extract_base_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_scope() {
        let f = ScopeFilter::new(ScopeKind::Domain, "http://www.example.com/app", vec![]);
        assert!(f.allows("http://www.example.com/"));
        assert!(f.allows("http://www.example.com/other"));
        assert!(!f.allows("http://evil.com/"));
        assert!(!f.allows("http://sub.example.com/"));
    }

    #[test]
    fn subdomains_scope() {
        let f = ScopeFilter::new(ScopeKind::Subdomains, "http://www.example.com/", vec![]);
        assert!(f.allows("http://www.example.com/"));
        assert!(f.allows("http://api.example.com/v1"));
        assert!(f.allows("http://example.com/"));
        assert!(!f.allows("http://evil.com/"));
    }

    #[test]
    fn folder_scope() {
        let f = ScopeFilter::new(ScopeKind::Folder, "http://example.com/app/", vec![]);
        assert!(f.allows("http://example.com/app/page"));
        assert!(!f.allows("http://example.com/other"));
    }

    #[test]
    fn exclude_pattern() {
        let rx = Regex::new(r"logout").unwrap();
        let f = ScopeFilter::new(ScopeKind::Domain, "http://example.com/", vec![rx]);
        assert!(f.allows("http://example.com/dashboard"));
        assert!(!f.allows("http://example.com/logout"));
    }
}
