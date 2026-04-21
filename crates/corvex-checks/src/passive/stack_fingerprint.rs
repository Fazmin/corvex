//! Stack fingerprint passive check.
//!
//! Runs the Wappalyzer-schema engine from `corvex-intel::fingerprint`
//! against each captured exchange and emits an Info finding that
//! enumerates detected stacks. The evidence shape matches a
//! Wappalyzer-style result so downstream tooling (the upcoming Banner
//! CVE check, the UI's stack badges) can consume it directly without
//! a second detection pass.

use std::sync::Arc;

use corvex_intel::fingerprint::{
    detect_any, DetectionInput, FingerprintLike, LoadedFingerprint, SEED_FINGERPRINTS,
};
use corvex_proxy::Exchange;
use serde_json::json;

use crate::check::{CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
use crate::finding::{Finding, Severity};

/// Stack fingerprint check. When a vendored Wappalyzer dataset is
/// present it runs that first and falls back to the compile-time seed
/// for anything the upstream doesn't cover. Both datasets share the
/// [`FingerprintLike`] trait so the detector visits them as one stream.
pub struct StackFingerprint {
    upstream: Arc<Vec<LoadedFingerprint>>,
}

impl StackFingerprint {
    pub fn new() -> Self {
        Self {
            upstream: Arc::new(Vec::new()),
        }
    }

    pub fn with_upstream(upstream: Arc<Vec<LoadedFingerprint>>) -> Self {
        Self { upstream }
    }
}

impl Default for StackFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveCheck for StackFingerprint {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "stack-fingerprint".into(),
            name: "Stack Fingerprint".into(),
            // 2025: Stack fingerprints inform supply-chain risk
            // (outdated versions, known-vulnerable components). The
            // new A03 Software Supply Chain Failures absorbed the
            // 2021 A06 Vulnerable and Outdated Components.
            category: OwaspCategory::A03(),
            kind: CheckKind::Passive,
            default_severity: Severity::Info,
            description:
                "Identifies the web framework, server and language stack behind each \
                 response using Wappalyzer-compatible matchers. Feeds the Banner CVE \
                 cross-reference and shows up as stack tags in Traffic."
                    .to_string(),
        }
    }

    fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        let Some(response) = &exchange.response else {
            return Vec::new();
        };

        // Flatten headers and cookies into `&[(&str, &str)]` for the
        // engine. Cookies are parsed from every `Set-Cookie` / Cookie
        // header we can see on the response + request.
        let headers: Vec<(&str, &str)> = response
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let mut cookie_buf: Vec<(String, String)> = Vec::new();
        for (k, v) in &response.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                if let Some((name, value)) = parse_set_cookie(v) {
                    cookie_buf.push((name, value));
                }
            }
        }
        for (k, v) in &exchange.request.headers {
            if k.eq_ignore_ascii_case("cookie") {
                for part in v.split(';') {
                    let part = part.trim();
                    if let Some((name, value)) = part.split_once('=') {
                        cookie_buf.push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
            }
        }
        let cookies: Vec<(&str, &str)> = cookie_buf
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let body = response.body_str();
        let body_ref: &str = body.as_ref();
        let path = split_path(&exchange.request.uri);

        let input = DetectionInput {
            headers: &headers,
            cookies: &cookies,
            body: body_ref,
            url_path: &path,
        };
        // Upstream dataset wins when present — it's far larger and
        // version-aware. The seed fills gaps for stacks the upstream
        // doesn't cover; `detect_any` dedupes by technology name so
        // there's no double-counting.
        let upstream_iter = self.upstream.iter().map(|f| f as &dyn FingerprintLike);
        let seed_iter = SEED_FINGERPRINTS.iter().map(|f| f as &dyn FingerprintLike);
        let chained = upstream_iter.chain(seed_iter);
        let detections = detect_any(&input, chained);

        if detections.is_empty() {
            return Vec::new();
        }

        let tags: Vec<String> = detections
            .iter()
            .map(|d| match &d.version {
                Some(v) => format!("{} {}", d.name, v),
                None => d.name.clone(),
            })
            .collect();

        let evidence = json!({
            "detections": detections,
            "attribution": "Wappalyzer-compatible schema — see crates/corvex-intel/data/LICENSE_NOTES.md",
        });

        vec![Finding::new(
            "stack-fingerprint",
            exchange.id,
            Severity::Info,
            format!("Stack detected: {}", tags.join(", ")),
        )
        .with_description(
            "Fingerprint evidence from HTTP headers, cookies, HTML and URL structure. \
             Useful on its own and required input for the Banner CVE cross-reference \
             in a follow-up iteration."
                .to_string(),
        )
        .with_evidence(evidence)]
    }
}

fn parse_set_cookie(raw: &str) -> Option<(String, String)> {
    let first = raw.split(';').next()?.trim();
    let (name, value) = first.split_once('=')?;
    Some((name.trim().to_string(), value.trim().to_string()))
}

fn split_path(uri: &str) -> String {
    uri.split_once('?')
        .map(|(p, _)| p.to_string())
        .unwrap_or_else(|| uri.to_string())
}
