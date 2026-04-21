//! Missing Security Headers (A05).

use corvex_intel::headers::{csp_has_frame_ancestors, OWASP_HEADER_BASELINE};
use corvex_proxy::Exchange;
use serde_json::json;

use crate::check::{CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
use crate::finding::{Finding, Severity};

pub struct SecurityHeaders;

impl PassiveCheck for SecurityHeaders {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "missing-security-headers".into(),
            name: "Missing Security Headers".into(),
            // 2025: Security Misconfiguration is now A02 (A05 in 2021).
            category: OwaspCategory::A02(),
            kind: CheckKind::Passive,
            default_severity: Severity::Low,
            description:
                "Reports each response missing a header from the OWASP Secure Headers Project baseline."
                    .to_string(),        }
    }

    fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        let Some(response) = &exchange.response else {
            return Vec::new();
        };
        let is_https = exchange.request.ssl;

        // Collect CSP so we can short-circuit X-Frame-Options when the
        // policy already covers frame-ancestors.
        let csp = header_ci(&response.headers, "Content-Security-Policy");

        let mut findings = Vec::new();
        for base in OWASP_HEADER_BASELINE {
            if base.https_only && !is_https {
                continue;
            }
            if header_ci(&response.headers, base.name).is_some() {
                continue;
            }
            if base.name == "X-Frame-Options" {
                if let Some(c) = csp.as_deref() {
                    if csp_has_frame_ancestors(c) {
                        continue;
                    }
                }
            }
            let severity: Severity = base.severity.into();
            let evidence = json!({
                "missing_header": base.name,
                "reference": base.reference,
            });
            findings.push(
                Finding::new(
                    self.descriptor().id,
                    exchange.id,
                    severity,
                    format!("Missing {} header", base.name),
                )
                .with_description(base.description.to_string())
                .with_evidence(evidence),
            );
        }
        findings
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
