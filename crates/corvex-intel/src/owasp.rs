//! OWASP Top 10 taxonomy — data-driven.
//!
//! Category metadata and classification rules live in
//! `data/owasp/top10.yaml`, embedded at build time via
//! `include_str!`. Updating OWASP to a new release is a YAML swap +
//! rebuild; no Rust source touches are needed unless you're adding
//! new rule primitives (e.g. URL patterns or tag-set intersections).

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

/// The YAML file shipped with the crate. Overwrite it to migrate to
/// a new OWASP release.
const EMBEDDED_YAML: &str = include_str!("../data/owasp/top10.yaml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspTaxonomy {
    /// Release label, e.g. `"2021"`.
    pub version: String,
    /// Release date as recorded by OWASP, e.g. `"2021-09-24"`.
    #[serde(default)]
    pub released: Option<String>,
    /// Upstream documentation URL.
    #[serde(default)]
    pub source: Option<String>,
    pub categories: Vec<CategoryDef>,
    /// Priority-ordered classification rules. First match wins.
    #[serde(default)]
    pub classify: Vec<ClassifyRule>,
    /// Catch-all code used when no rule matches. Must exist in
    /// `categories`.
    pub default_category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryDef {
    pub code: String,
    pub label: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyRule {
    /// List of match patterns; any one matching triggers the rule.
    pub any: Vec<String>,
    /// The category code to assign when this rule fires.
    pub category: String,
}

impl OwaspTaxonomy {
    /// Look up the display label for a category code. Returns `None`
    /// if the code isn't present in the taxonomy.
    pub fn label(&self, code: &str) -> Option<&str> {
        self.categories
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
            .map(|c| c.label.as_str())
    }

    pub fn category(&self, code: &str) -> Option<&CategoryDef> {
        self.categories
            .iter()
            .find(|c| c.code.eq_ignore_ascii_case(code))
    }

    /// Classify by tag list + identifier (template id or check name).
    /// Returns the category code string. Falls back to
    /// `default_category` when no rule matches.
    pub fn classify(&self, tags: &[String], id_or_name: &str) -> &str {
        let tags_lower: Vec<String> =
            tags.iter().map(|t| t.to_ascii_lowercase()).collect();
        let name_lower = id_or_name.to_ascii_lowercase();

        for rule in &self.classify {
            if rule.any.iter().any(|pat| pattern_matches(pat, &tags_lower, &name_lower)) {
                return &rule.category;
            }
        }
        &self.default_category
    }
}

fn pattern_matches(pattern: &str, tags_lower: &[String], name_lower: &str) -> bool {
    let (kind, needle) = match pattern.split_once(':') {
        Some((k, n)) => (k, n.to_ascii_lowercase()),
        None => return false, // malformed entry — do not match
    };
    match kind {
        "tag" => tags_lower.iter().any(|t| t.contains(&needle)),
        "name" => name_lower.contains(&needle),
        _ => false,
    }
}

/// Parse the embedded YAML once on first access. Any YAML / schema
/// error panics the process — the taxonomy is load-bearing, so we
/// fail loudly rather than silently running with a wrong taxonomy.
static DEFAULT_TAXONOMY: Lazy<OwaspTaxonomy> = Lazy::new(|| {
    serde_yaml::from_str(EMBEDDED_YAML).expect("OWASP top10.yaml must parse")
});

/// Return the taxonomy bundled with the binary.
pub fn default_taxonomy() -> &'static OwaspTaxonomy {
    &DEFAULT_TAXONOMY
}

/// Convenience: classify using the default taxonomy. Returns an
/// owned String because most call sites need it that way.
pub fn classify(tags: &[String], id_or_name: &str) -> String {
    default_taxonomy().classify(tags, id_or_name).to_string()
}

/// Convenience: look up a label. Falls back to "Uncategorised".
pub fn label_for(code: &str) -> String {
    default_taxonomy()
        .label(code)
        .unwrap_or("Uncategorised")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn yaml_parses_and_has_ten_categories() {
        let tax = default_taxonomy();
        assert_eq!(tax.categories.len(), 10, "Top 10 should have 10 entries");
    }

    #[test]
    fn default_category_is_defined() {
        let tax = default_taxonomy();
        assert!(
            tax.category(&tax.default_category).is_some(),
            "default_category must exist in categories",
        );
    }

    #[test]
    fn every_classify_rule_references_a_known_category() {
        let tax = default_taxonomy();
        for rule in &tax.classify {
            assert!(
                tax.category(&rule.category).is_some(),
                "classify rule references unknown category {}",
                rule.category,
            );
        }
    }

    // ------------------------------------------------------------------
    // 2025-specific classifier expectations. When the YAML is swapped
    // to a future release, update these to match the new mapping.
    // ------------------------------------------------------------------

    #[test]
    fn sqli_tag_classifies_injection() {
        // 2025: Injection is A05 (was A03 in 2021).
        assert_eq!(classify(&t(&["cves", "sqli"]), "CVE-2023-0001"), "A05");
    }

    #[test]
    fn ssrf_is_injection_family_in_2025() {
        // 2025: SSRF is folded into A05 Injection. 2021 had a dedicated
        // A10. The classifier routes SSRF tags to A05 and that wins
        // against bare `cve`, which would otherwise land at A03.
        assert_eq!(classify(&t(&["cve", "ssrf"]), "CVE-1"), "A05");
    }

    #[test]
    fn bare_cve_is_supply_chain() {
        // 2025: Vulnerable/outdated components are absorbed into A03
        // Software Supply Chain Failures.
        assert_eq!(classify(&t(&["cves"]), "cve-2024-9999"), "A03");
    }

    #[test]
    fn exposure_falls_to_default() {
        // 2025 default is A02 Security Misconfiguration (was A05 in 2021).
        assert_eq!(
            classify(&t(&["exposure", "misc"]), "panel-detect"),
            "A02",
        );
    }

    #[test]
    fn log4j_routes_to_supply_chain() {
        // 2025: log4j is a vulnerable-component / supply-chain issue.
        // The `name:log4j` rule fires before the generic `tag:rce` rule
        // so the assignment is A03 even when `rce` / `logs` tags are
        // present.
        assert_eq!(classify(&t(&["cve", "logs"]), "log4j-rce"), "A03");
    }
}
