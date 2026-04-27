//! Reflected XSS active check (A03).
//!
//! For each query parameter we send a request with a unique canary
//! token, check whether the token is reflected into the response, and
//! then step through context-breakers looking for an unencoded
//! reflection. Reports only when an unencoded reflection lands — a
//! plain bounce without context break is signal enough for Info, but
//! we skip it here to keep noise down.

use async_trait::async_trait;
use corvex_intel::payloads::xss_canary_context_breakers;
use corvex_proxy::Exchange;
use rand::Rng;
use serde_json::json;

use crate::active::with_param_payload;
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

pub struct ReflectedXss;

#[async_trait]
impl ActiveCheck for ReflectedXss {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "reflected-xss".into(),
            name: "Reflected XSS".into(),
            // 2025: Injection moved to A05 (from A03 in 2021).
            category: OwaspCategory::A05(),
            kind: CheckKind::Active,
            default_severity: Severity::High,
            description:
                "Injects a unique canary into each query parameter and reports parameters \
                 that reflect the canary unencoded in HTML/attribute/script contexts."
                    .to_string(),        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        let mut findings = Vec::new();
        let canary = format!("cvxXSS{:x}", rand::thread_rng().gen::<u64>());

        for (context_name, template) in xss_canary_context_breakers() {
            let payload = template.replace("__CVX_CANARY__", &canary);
            for (param, mutated) in with_param_payload(&target.request, &payload) {
                let resp = match ctx.send_with_csrf(&mutated).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let body = resp.body_str();
                if !body.contains(&canary) {
                    continue;
                }
                // Heuristic: if the canary survives in its
                // context-breaking form (literal payload present),
                // the browser will render it. For the plain variant
                // we require the context breakers to be literal too.
                if !body.contains(&payload) {
                    continue;
                }
                findings.push(
                    Finding::new(
                        "reflected-xss",
                        target.id,
                        Severity::High,
                        format!(
                            "Reflected XSS in `{param}` (context: {context_name})"
                        ),
                    )
                    .with_description(
                        "The supplied payload was reflected unencoded in the response, \
                         indicating the parameter value is rendered without contextual \
                         escaping."
                            .to_string(),                    )
                    .with_evidence(json!({
                        "param": param,
                        "payload": payload,
                        "canary": canary,
                        "context": context_name,
                    })),
                );
                // One finding per (param, context) is enough; break
                // out so we don't flood the UI with variants of the
                // same issue.
                break;
            }
        }
        findings
    }
}
