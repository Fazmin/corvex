//! Boolean-blind SQL injection (A03 — Injection).
//!
//! For each query parameter, we send two probes that differ by a
//! single boolean fact (`AND 1=1` vs `AND 1=2`). If the "true" probe
//! renders a page that's significantly similar to the baseline and the
//! "false" probe renders a page that's significantly different — and
//! the two probes differ from each other — we have attacker-controlled
//! boolean branching in a SQL statement.
//!
//! The page-similarity math lives in
//! [`corvex_core::sqli::detection`] (same trigram-based ratio sqlmap
//! uses), including dynamic-content stripping so CSRF tokens and
//! timestamps don't poison the comparison.
//!
//! The check iterates the boundary variants in [`SQLI_BOUNDARIES`]
//! (numeric / single-quote / double-quote / paren-quote) and stops on
//! the first confirmed boundary per parameter. That keeps the request
//! count bounded even on APIs with dozens of parameters.

use async_trait::async_trait;
use corvex_core::http::request::Request as CoreReq;
use corvex_core::http::response::Response as CoreResp;
use corvex_core::sqli::detection::{page_ratio, remove_dynamic_content};
use corvex_proxy::Exchange;
use serde_json::json;

use crate::active::{with_param_value, SqliBoundary, SQLI_BOUNDARIES};
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

pub struct BooleanBlindSqli;

/// Minimum similarity between baseline and the TRUE probe for the
/// oracle to consider them "the same page". sqlmap's default is ~0.98;
/// we pick 0.90 because captured traffic often includes nonce-laden
/// HTML that [`remove_dynamic_content`] can't fully normalise.
const TRUE_MIN_RATIO: f64 = 0.90;

/// Maximum similarity between baseline and the FALSE probe for the
/// oracle to consider them "different pages".
const FALSE_MAX_RATIO: f64 = 0.80;

/// TRUE and FALSE responses must themselves differ by at least this
/// much — catches endpoints that echo the raw query string into the
/// response (TRUE will look almost identical to FALSE then).
const TRUE_FALSE_GAP: f64 = 0.05;

#[async_trait]
impl ActiveCheck for BooleanBlindSqli {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "boolean-blind-sqli".into(),
            name: "Boolean-blind SQL Injection".into(),
            category: OwaspCategory::A05(),
            kind: CheckKind::Active,
            default_severity: Severity::High,
            description: "Injects `AND 1=1` / `AND 1=2` variants per parameter and \
                 compares response similarity against the baseline. A \
                 TRUE probe that matches the baseline while the FALSE probe \
                 diverges indicates boolean-controllable SQL. Works against \
                 numeric, single-quote, double-quote and paren-quote contexts."
                .to_string(),
        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        let Ok(baseline) = ctx.client.send(&target.request).await else {
            return Vec::new();
        };
        let baseline_body = normalise(baseline.body.as_slice());

        let mut findings = Vec::new();
        let mut param_hit: std::collections::HashSet<String> = std::collections::HashSet::new();

        for boundary in SQLI_BOUNDARIES {
            // Rebuild the parameter-mutation list on every boundary so
            // each parameter gets a fresh shot even if an earlier
            // boundary already cleared it (the hit-set below suppresses
            // duplicates).
            let true_probes = with_param_value(&target.request, |_, original| {
                build_probe(original, boundary, "1=1")
            });
            let false_probes = with_param_value(&target.request, |_, original| {
                build_probe(original, boundary, "1=2")
            });

            for ((name, original, req_true), (_, _, req_false)) in
                true_probes.into_iter().zip(false_probes.into_iter())
            {
                if param_hit.contains(&name) {
                    continue;
                }
                let Ok(r_true) = ctx.client.send(&req_true).await else {
                    continue;
                };
                let Ok(r_false) = ctx.client.send(&req_false).await else {
                    continue;
                };

                // Skip pathological responses where the two probes
                // landed on error pages that differ only in length /
                // headers — a bound page would still respond 200.
                if status_class(&r_true) != status_class(&baseline)
                    || status_class(&r_false) != status_class(&baseline)
                {
                    continue;
                }

                let body_true = normalise(r_true.body.as_slice());
                let body_false = normalise(r_false.body.as_slice());

                let ratio_true = page_ratio(baseline_body.as_bytes(), body_true.as_bytes());
                let ratio_false = page_ratio(baseline_body.as_bytes(), body_false.as_bytes());
                let ratio_tf = page_ratio(body_true.as_bytes(), body_false.as_bytes());

                let hit = ratio_true >= TRUE_MIN_RATIO
                    && ratio_false <= FALSE_MAX_RATIO
                    && (1.0 - ratio_tf) >= TRUE_FALSE_GAP;

                if !hit {
                    continue;
                }
                param_hit.insert(name.clone());

                findings.push(
                    Finding::new(
                        "boolean-blind-sqli",
                        target.id,
                        Severity::High,
                        format!("Boolean-blind SQL injection in `{name}`"),
                    )
                    .with_description(
                        "The parameter steers the SQL query's WHERE clause: the AND 1=1 \
                         probe returned the baseline page and AND 1=2 returned a \
                         different page. This confirms an attacker can read data by \
                         changing truth-value questions, even when the application \
                         suppresses database errors."
                            .to_string(),
                    )
                    .with_evidence(json!({
                        "param": name,
                        "original_value": original,
                        "boundary": boundary.label,
                        "true_payload": build_probe(&original, boundary, "1=1"),
                        "false_payload": build_probe(&original, boundary, "1=2"),
                        "ratio_true_vs_baseline": round3(ratio_true),
                        "ratio_false_vs_baseline": round3(ratio_false),
                        "ratio_true_vs_false": round3(ratio_tf),
                        "thresholds": {
                            "true_min": TRUE_MIN_RATIO,
                            "false_max": FALSE_MAX_RATIO,
                            "gap": TRUE_FALSE_GAP,
                        },
                    })),
                );
            }
        }

        findings
    }
}

/// Assemble the probe value — preserves the original (so the app's
/// own parser keeps accepting the value shape) and tacks the boolean
/// condition on using the chosen boundary.
pub(crate) fn build_probe(original: &str, boundary: &SqliBoundary, cond: &str) -> String {
    // `original <prefix> AND <cond><trailer>`
    // Spaces either side of AND so tokens don't merge into the original
    // value (`5'AND` vs `5' AND`).
    format!(
        "{original}{prefix} AND {cond}{trailer}",
        prefix = boundary.prefix,
        trailer = boundary.trailer,
    )
}

fn normalise(body: &[u8]) -> String {
    let raw = String::from_utf8_lossy(body).to_string();
    remove_dynamic_content(&raw)
}

fn status_class(resp: &CoreResp) -> u16 {
    (resp.status / 100) as u16
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

// Suppress the unused-import warning for types only referenced in type
// positions above.
#[allow(dead_code)]
fn _type_hints(_r: &CoreReq) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_preserves_original_value_and_adds_boundary() {
        let numeric = &SQLI_BOUNDARIES[0];
        assert_eq!(
            build_probe("5", numeric, "1=1"),
            "5 AND 1=1-- -",
            "numeric boundary should leave the value bare"
        );

        let quote = &SQLI_BOUNDARIES[1];
        assert_eq!(
            build_probe("abc", quote, "1=2"),
            "abc' AND 1=2-- -",
            "single-quote boundary should append a single quote"
        );
    }

    #[test]
    fn all_boundaries_have_distinct_labels() {
        let mut seen = std::collections::HashSet::new();
        for b in SQLI_BOUNDARIES {
            assert!(seen.insert(b.label), "duplicate boundary label {}", b.label);
        }
    }

    #[test]
    fn descriptor_advertises_active_a05_high() {
        let d = BooleanBlindSqli.descriptor();
        assert_eq!(d.id, "boolean-blind-sqli");
        assert_eq!(d.kind, CheckKind::Active);
        assert_eq!(d.category.code(), "A05");
        assert_eq!(d.default_severity, Severity::High);
    }
}
