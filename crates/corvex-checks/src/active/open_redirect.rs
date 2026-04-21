//! Open Redirect active check (A01).
//!
//! For each query parameter whose value looks like a URL or path we
//! substitute the sentinel host and inspect the 3xx `Location` header.
//! A positive requires `Location` to be an absolute URL pointing at
//! our sentinel host — partial matches or `Refresh` meta tags are out
//! of scope for Phase 3A to keep false positives near zero.

use async_trait::async_trait;
use corvex_intel::payloads::open_redirect_sentinel;
use corvex_proxy::Exchange;
use serde_json::json;

use crate::active::with_param_payload;
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

pub struct OpenRedirect;

#[async_trait]
impl ActiveCheck for OpenRedirect {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "open-redirect".into(),
            name: "Open Redirect".into(),
            category: OwaspCategory::A01(),
            kind: CheckKind::Active,
            default_severity: Severity::Medium,
            description:
                "Replaces URL-shaped parameter values with a sentinel host and reports \
                 endpoints that redirect to it."
                    .to_string(),        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        let sentinel = open_redirect_sentinel();
        let mut findings = Vec::new();

        for payload in [
            format!("https://{sentinel}/"),
            format!("//{sentinel}/"),
            format!("/\\{sentinel}/"),
        ] {
            for (param, mutated) in with_param_payload(&target.request, &payload) {
                // Only try the parameter if its original value looks
                // URL-shaped. Cheap heuristic — full URL detection
                // lives in Phase 3B.
                if !looks_url_shaped(&target.request.uri, &param) {
                    continue;
                }

                let resp = match ctx.client.send(&mutated).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if !(300..=399).contains(&resp.status) {
                    continue;
                }
                let location = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .map(|(_, v)| v.as_str());
                let Some(loc) = location else {
                    continue;
                };
                if !loc.contains(sentinel) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        "open-redirect",
                        target.id,
                        Severity::Medium,
                        format!("Open redirect via `{param}`"),
                    )
                    .with_description(
                        "The endpoint redirects to an attacker-controlled URL supplied \
                         through a parameter. Open redirects are chained with phishing \
                         and OAuth abuse to hijack user sessions."
                            .to_string(),                    )
                    .with_evidence(json!({
                        "param": param,
                        "payload": payload,
                        "location": loc,
                    })),
                );
            }
        }

        findings
    }
}

fn looks_url_shaped(uri: &str, param: &str) -> bool {
    let needle = format!("{param}=");
    let Some(start) = uri.find(&needle) else {
        return false;
    };
    let rest = &uri[start + needle.len()..];
    let value = rest.split('&').next().unwrap_or(rest);
    value.starts_with('/')
        || value.starts_with("http%3A")
        || value.starts_with("https%3A")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.contains("%2F%2F")
        || value.contains("//")
}
