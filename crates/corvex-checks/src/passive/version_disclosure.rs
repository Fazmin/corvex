//! Version Disclosure (A06). Extracts product+version banners from
//! common response headers and HTML generator meta tags.

use corvex_proxy::Exchange;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;

use crate::check::{CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
use crate::finding::{Finding, Severity};

// Any `name[/ ]?version` style banner. Match only when a digit is
// present so plain "Server: nginx" without a version isn't flagged —
// knowing the product alone is weak signal compared to
// product+version.
static VERSIONED_BANNER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([A-Za-z][\w.-]+)[/ ]?(\d+(?:\.\d+){1,3}[\w.-]*)").unwrap());

static GENERATOR_META: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)<meta\s+name=["']generator["']\s+content=["']([^"'\d]*\d[^"']*)["']\s*/?>"#,
    )
    .unwrap()
});

pub struct VersionDisclosure;

impl PassiveCheck for VersionDisclosure {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "version-disclosure".into(),
            name: "Version Disclosure".into(),
            // 2025: Product/version banners are load-bearing input for
            // supply-chain risk, which is now its own category (A03
            // Software Supply Chain Failures — absorbed the 2021 A06
            // Vulnerable and Outdated Components).
            category: OwaspCategory::A03(),
            kind: CheckKind::Passive,
            default_severity: Severity::Info,
            description:
                "Identifies version banners in Server / X-Powered-By / X-AspNet-Version / \
                 generator meta tags. Useful on its own and required for the Banner-CVE \
                 cross-reference check."
                    .to_string(),        }
    }

    fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        let Some(response) = &exchange.response else {
            return Vec::new();
        };

        let mut banners: Vec<(String, String, String)> = Vec::new();
        for header_name in &[
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
        ] {
            if let Some(value) = header_ci(&response.headers, header_name) {
                if let Some(cap) = VERSIONED_BANNER.captures(&value) {
                    banners.push((
                        header_name.to_string(),
                        cap.get(1).unwrap().as_str().to_string(),
                        cap.get(2).unwrap().as_str().to_string(),
                    ));
                }
            }
        }

        // HTML <meta name=generator> extraction.
        let ct = header_ci(&response.headers, "Content-Type").unwrap_or_default();
        if ct.contains("html") {
            let body = response.body_str();
            if let Some(cap) = GENERATOR_META.captures(body.as_ref()) {
                banners.push((
                    "<meta generator>".to_string(),
                    "html".to_string(),
                    cap.get(1).unwrap().as_str().trim().to_string(),
                ));
            }
        }

        if banners.is_empty() {
            return Vec::new();
        }

        vec![Finding::new(
            "version-disclosure",
            exchange.id,
            Severity::Info,
            "Server advertises product versions",
        )
        .with_description(
            "Version banners make targeted exploit lookups easier. Remove or replace \
             with a generic identifier unless your ops team relies on them."
                .to_string(),        )
        .with_evidence(json!({ "banners": banners }))]
    }
}

fn header_ci(
    headers: &indexmap::IndexMap<String, String>,
    name: &str,
) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}
