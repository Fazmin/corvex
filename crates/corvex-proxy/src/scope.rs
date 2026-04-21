//! Scope rule engine.
//!
//! Scope classifies a request as `InScope`, `OutOfScope`, or
//! `Excluded`. The traffic log captures every request regardless, but
//! interactive features (intercept, replay edits, active checks) gate
//! their behaviour on scope so that incidental browser traffic from
//! other tabs can't be accidentally tampered with.

use regex::Regex;
use serde::{Deserialize, Serialize};

pub use crate::exchange::ScopeDecision;

/// A single rule that matches against a request's host and/or path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    /// Host pattern. Supports exact match and leading `*.` wildcard
    /// (e.g. `*.example.com`). Empty string means "any host".
    #[serde(default)]
    pub host: String,
    /// Optional path regex. Empty or missing means "any path".
    #[serde(default)]
    pub path_regex: Option<String>,
    /// Optional port filter; `None` means "any port".
    #[serde(default)]
    pub port: Option<u16>,
}

impl ScopeRule {
    fn matches(&self, host: &str, port: u16, path: &str) -> bool {
        if !host_matches(&self.host, host) {
            return false;
        }
        if let Some(p) = self.port {
            if p != port {
                return false;
            }
        }
        if let Some(pat) = &self.path_regex {
            match Regex::new(pat) {
                Ok(re) => {
                    if !re.is_match(path) {
                        return false;
                    }
                }
                // Malformed patterns fail closed (do not match) so a bad
                // rule never widens scope silently.
                Err(_) => return false,
            }
        }
        true
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.eq_ignore_ascii_case(suffix)
            || host.to_ascii_lowercase().ends_with(&format!(
                ".{}",
                suffix.to_ascii_lowercase()
            ));
    }
    host.eq_ignore_ascii_case(pattern)
}

/// Full scope configuration: include rules, exclude rules, and the
/// behaviour when no includes are configured.
///
/// Matches the user-chosen default: the traffic log captures
/// everything; in-scope/out-of-scope only gates active features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRules {
    /// If empty, every request is treated as `InScope` (per user's
    /// chosen default "log all, scope gates active features").
    #[serde(default)]
    pub include: Vec<ScopeRule>,
    #[serde(default)]
    pub exclude: Vec<ScopeRule>,
}

impl Default for ScopeRules {
    fn default() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

impl ScopeRules {
    pub fn classify(&self, host: &str, port: u16, path: &str) -> ScopeDecision {
        for rule in &self.exclude {
            if rule.matches(host, port, path) {
                return ScopeDecision::Excluded;
            }
        }
        if self.include.is_empty() {
            return ScopeDecision::InScope;
        }
        for rule in &self.include {
            if rule.matches(host, port, path) {
                return ScopeDecision::InScope;
            }
        }
        ScopeDecision::OutOfScope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rules_everything_in_scope() {
        let rules = ScopeRules::default();
        assert_eq!(
            rules.classify("example.com", 443, "/foo"),
            ScopeDecision::InScope
        );
    }

    #[test]
    fn host_wildcard_matches_subdomains() {
        let rules = ScopeRules {
            include: vec![ScopeRule {
                host: "*.example.com".into(),
                path_regex: None,
                port: None,
            }],
            exclude: vec![],
        };
        assert_eq!(
            rules.classify("api.example.com", 443, "/"),
            ScopeDecision::InScope
        );
        assert_eq!(
            rules.classify("example.com", 443, "/"),
            ScopeDecision::InScope
        );
        assert_eq!(
            rules.classify("other.org", 443, "/"),
            ScopeDecision::OutOfScope
        );
    }

    #[test]
    fn exclude_wins_over_include() {
        let rules = ScopeRules {
            include: vec![ScopeRule {
                host: "*.example.com".into(),
                path_regex: None,
                port: None,
            }],
            exclude: vec![ScopeRule {
                host: "telemetry.example.com".into(),
                path_regex: None,
                port: None,
            }],
        };
        assert_eq!(
            rules.classify("telemetry.example.com", 443, "/"),
            ScopeDecision::Excluded
        );
    }
}
