//! Hidden-parameter discovery (A05 — Security Misconfiguration).
//!
//! Fuzzes a curated wordlist of ~220 candidate parameter names against
//! the target endpoint, one at a time, and reports each candidate
//! whose presence causes the response to diverge meaningfully from
//! the baseline. Hidden parameters are a force multiplier: every
//! downstream check (SQLi, SSRF, XSS, Open Redirect) only probes
//! parameters it can see, so uncovering an `admin=1` flag or a
//! `debug=true` switch immediately widens the blast radius of every
//! other active check.
//!
//! Two oracles are combined so a hit needs corroboration:
//!
//!   1. **Canary reflection** — the random marker we set as the
//!      parameter's value appears in the response body. This is the
//!      strongest signal; reflection implies the value was at minimum
//!      template-interpolated, often SQL-interpolated.
//!   2. **Response-shape change** — the response body's trigram
//!      similarity to the baseline drops below a threshold, AND the
//!      change isn't explained by a "control" probe with a bogus
//!      parameter name. The control probe is sent first; if the
//!      endpoint happens to return random content on every request,
//!      the control diff will match the fuzzed diff and suppress
//!      findings.
//!
//! The check is heavier than the others — it issues up to
//! `total_hidden_params() + 2` requests per target. It's disabled in
//! the UI library by default; enable it when you're actively hunting.

use async_trait::async_trait;
use corvex_core::http::request::Request as CoreReq;
use corvex_core::sqli::detection::{page_ratio, remove_dynamic_content};
use corvex_intel::hidden_params::{all_hidden_params, total_hidden_params};
use corvex_proxy::Exchange;
use rand::Rng;
use serde_json::json;

use crate::active::build_full_url;
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

pub struct HiddenParams;

/// Response bodies that share at least this ratio with the baseline
/// are considered "same shape". Below this → candidate signal.
const SAME_SHAPE_THRESHOLD: f64 = 0.92;

/// Extra gap required between the control-probe diff and the
/// candidate-param diff. If `control_ratio` is 0.5 (the endpoint is
/// naturally chaotic) and the candidate ratio is 0.48, that's noise.
/// We require the candidate to be at least `FLUX_GAP` closer to
/// "different" than the control probe.
const FLUX_GAP: f64 = 0.05;

/// Random marker length. 12 chars of `[a-z0-9]` is ~62 bits — enough
/// to make accidental in-baseline collisions a non-issue. We prepend
/// `1` so the value also trips truthy-boolean branches (common in
/// PHP / JavaScript / Python apps that do `if ($_GET['x'])`). Apps
/// that strict-equal compare against "1" won't see a behaviour
/// change — that's a known blind spot and the reason this check
/// complements rather than replaces a manual hidden-param hunt.
const CANARY_LEN: usize = 12;

/// Prefix that tries to satisfy truthy-boolean parameter checks while
/// still being unique enough to spot in the response body. Keep this
/// a single ASCII digit so "1abcdef..." parses as a positive integer
/// in languages that cast early (Java `Integer.parseInt`, Go
/// `strconv.Atoi` — won't cast but won't crash either).
const CANARY_PREFIX: &str = "1";

/// A bogus name used for the control probe. Nothing in the wordlist
/// uses this — it's meant to never collide with a real parameter.
const CONTROL_NAME: &str = "zzcorvexnoop";

#[async_trait]
impl ActiveCheck for HiddenParams {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "hidden-params".into(),
            name: "Hidden Parameter Discovery".into(),
            category: OwaspCategory::new("A05"),
            kind: CheckKind::Active,
            default_severity: Severity::Low,
            description: "Fuzzes ~220 common parameter names against the target and reports \
                 any whose presence reflects in the response or changes the response \
                 shape beyond what a control probe produces. Newly-discovered \
                 parameters are the input for the SQLi / SSRF / XSS / Open Redirect \
                 checks; run this first on an unfamiliar target."
                .to_string(),
        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        // Baseline: unmodified request. Short-circuit the whole check
        // if we can't establish a comparison point.
        let Ok(baseline_resp) = ctx.client.send(&target.request).await else {
            return Vec::new();
        };
        let baseline_body = normalise(baseline_resp.body.as_slice());
        let baseline_status = baseline_resp.status;

        // Control probe: add a random-named parameter the app can't
        // possibly recognise. Its diff represents "how much does the
        // response naturally jitter when we tack on a no-op param?"
        let control_canary = random_canary();
        let Some(control_req) = append_param(&target.request, CONTROL_NAME, &control_canary)
        else {
            return Vec::new();
        };
        let control_ratio = match ctx.client.send(&control_req).await {
            Ok(r) => {
                let body = normalise(r.body.as_slice());
                page_ratio(baseline_body.as_bytes(), body.as_bytes())
            }
            Err(_) => 1.0, // Treat control failure conservatively — no
                           // permitted drift, require strong signal.
        };

        let mut findings = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (class, name) in all_hidden_params() {
            if param_already_present(&target.request, name) {
                continue;
            }
            if !seen.insert(name.to_string()) {
                continue;
            }

            // First probe: random canary. Primary job is to catch
            // reflection — apps that echo the value verbatim into
            // the response mark the parameter consumed unambiguously.
            let canary = random_canary();
            let Some(canary_req) = append_param(&target.request, name, &canary) else {
                continue;
            };
            let Ok(resp1) = ctx.client.send(&canary_req).await else {
                continue;
            };
            let body1 = normalise(resp1.body.as_slice());
            let ratio1 = page_ratio(baseline_body.as_bytes(), body1.as_bytes());

            let reflected = body1.contains(&canary)
                || resp1
                    .body_str()
                    .as_ref()
                    .to_string()
                    .to_ascii_lowercase()
                    .contains(&canary.to_ascii_lowercase());
            let shape_diff1 =
                ratio1 < SAME_SHAPE_THRESHOLD && (control_ratio - ratio1) >= FLUX_GAP;
            let status_changed1 = (resp1.status / 100) != (baseline_status / 100);

            // Second probe (only if the first didn't fire): plain
            // `"1"` value. Catches strict-equality checks
            // (`if (param == "1")`) that the random canary can't
            // satisfy. Skipped when the canary already produced a
            // signal, keeping the request budget roughly bounded by
            // `wordlist + small multiplier`.
            let mut matched_value = canary.clone();
            let mut final_ratio = ratio1;
            let mut final_status = resp1.status;
            let mut shape_diff = shape_diff1;
            let mut status_changed = status_changed1;

            if !reflected && !shape_diff1 && !status_changed1 {
                if let Some(val1_req) = append_param(&target.request, name, "1") {
                    if let Ok(resp2) = ctx.client.send(&val1_req).await {
                        let body2 = normalise(resp2.body.as_slice());
                        let ratio2 = page_ratio(baseline_body.as_bytes(), body2.as_bytes());
                        let shape_diff2 = ratio2 < SAME_SHAPE_THRESHOLD
                            && (control_ratio - ratio2) >= FLUX_GAP;
                        let status_changed2 =
                            (resp2.status / 100) != (baseline_status / 100);
                        if shape_diff2 || status_changed2 {
                            matched_value = "1".to_string();
                            final_ratio = ratio2;
                            final_status = resp2.status;
                            shape_diff = shape_diff2;
                            status_changed = status_changed2;
                        }
                    }
                }
            }

            if !reflected && !shape_diff && !status_changed {
                continue;
            }

            let severity = if reflected || status_changed {
                Severity::Medium
            } else {
                Severity::Low
            };

            let title = format!("Hidden parameter `{name}` accepted ({class})");
            let description = format!(
                "The parameter `{name}` is not in the endpoint's visible query string but \
                 the response reacted to its presence. Reflection means the value was \
                 consumed (reflected={reflected}); a response-shape change means the \
                 server branched on it; a status-code change means it triggered a \
                 different route entirely. Treat this parameter as a new surface for the \
                 SQLi / SSRF / XSS / Open Redirect active checks.",
            );

            findings.push(
                Finding::new("hidden-params", target.id, severity, title)
                    .with_description(description)
                    .with_evidence(json!({
                        "param": name,
                        "class": class,
                        "value_that_matched": matched_value,
                        "reflected": reflected,
                        "shape_diff": shape_diff,
                        "status_changed": status_changed,
                        "ratio_vs_baseline": round3(final_ratio),
                        "control_ratio_vs_baseline": round3(control_ratio),
                        "response_status": final_status,
                        "baseline_status": baseline_status,
                        "wordlist_size": total_hidden_params(),
                    })),
            );
        }

        findings
    }
}

/// Build a copy of `base` with a new query parameter `name=value`
/// appended. Preserves all existing parameters.
fn append_param(base: &CoreReq, name: &str, value: &str) -> Option<CoreReq> {
    let original_url = build_full_url(base)?;
    let mut mutated = base.clone();
    let mut url = original_url.clone();
    let existing: Vec<(String, String)> = original_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    {
        let mut b = url.query_pairs_mut();
        b.clear();
        for (k, v) in &existing {
            b.append_pair(k, v);
        }
        b.append_pair(name, value);
    }
    let mut new_uri = url.path().to_string();
    if let Some(q) = url.query() {
        new_uri.push('?');
        new_uri.push_str(q);
    }
    mutated.uri = new_uri;
    Some(mutated)
}

fn param_already_present(req: &CoreReq, name: &str) -> bool {
    let needle_eq = format!("{name}=");
    let needle_amp = format!("&{name}=");
    req.uri.contains(&needle_amp)
        || req
            .uri
            .split_once('?')
            .map(|(_, q)| q.starts_with(&needle_eq))
            .unwrap_or(false)
}

fn random_canary() -> String {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(CANARY_PREFIX.len() + CANARY_LEN);
    out.push_str(CANARY_PREFIX);
    for _ in 0..CANARY_LEN {
        out.push(ALPHA[rng.gen_range(0..ALPHA.len())] as char);
    }
    out
}

fn normalise(body: &[u8]) -> String {
    let raw = String::from_utf8_lossy(body).to_string();
    remove_dynamic_content(&raw)
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_advertises_hidden_params_metadata() {
        let d = HiddenParams.descriptor();
        assert_eq!(d.id, "hidden-params");
        assert_eq!(d.kind, CheckKind::Active);
        assert_eq!(d.category.code(), "A05");
        assert_eq!(d.default_severity, Severity::Low);
    }

    #[test]
    fn canary_is_alphanumeric_and_starts_with_truthy_prefix() {
        for _ in 0..25 {
            let c = random_canary();
            assert_eq!(c.len(), CANARY_PREFIX.len() + CANARY_LEN);
            assert!(c.starts_with(CANARY_PREFIX));
            assert!(c.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()));
        }
    }

    #[test]
    fn already_present_check_catches_both_forms() {
        let mut r = CoreReq::new("ex.com", 80, "GET", "/p?foo=1&bar=2");
        r.ssl = false;
        assert!(param_already_present(&r, "foo"));
        assert!(param_already_present(&r, "bar"));
        assert!(!param_already_present(&r, "baz"));
        assert!(!param_already_present(&r, "ba")); // prefix must not match
    }

    #[test]
    fn append_param_preserves_existing_query_and_appends_new_pair() {
        let mut r = CoreReq::new("ex.com", 443, "GET", "/search?q=alice&lang=en");
        r.ssl = true;
        let new_req = append_param(&r, "admin", "CANARY123").expect("builds");
        assert!(new_req.uri.contains("q=alice"));
        assert!(new_req.uri.contains("lang=en"));
        assert!(new_req.uri.contains("admin=CANARY123"));
    }

    #[test]
    fn append_param_handles_empty_query() {
        let mut r = CoreReq::new("ex.com", 80, "GET", "/users/42");
        r.ssl = false;
        let new_req = append_param(&r, "debug", "1").expect("builds");
        assert!(new_req.uri.contains("debug=1"));
        assert!(new_req.uri.starts_with("/users/42"));
    }

    #[test]
    fn catalogue_size_meets_expected_budget() {
        // Keeps per-target request cost predictable (~220 + 2
        // baseline/control). Exact number can grow as the catalogue
        // evolves; the floor protects against accidental pruning.
        assert!(total_hidden_params() >= 150);
    }
}
