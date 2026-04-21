//! Error-based SQL injection active check (A03).
//!
//! Reuses the DBMS error-signature bank in corvex-core. For each query
//! parameter we send a set of boundary-breaking payloads and report
//! parameters that induce a signature we didn't see in the baseline
//! response.

use std::collections::HashSet;

use async_trait::async_trait;
use corvex_core::sqli::detection::error_matches;
use corvex_intel::payloads::sqli_error_probes;
use corvex_proxy::Exchange;
use serde_json::json;

use crate::active::with_param_payload;
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

pub struct ErrorBasedSqli;

#[async_trait]
impl ActiveCheck for ErrorBasedSqli {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "error-based-sqli".into(),
            name: "Error-based SQL Injection".into(),
            // 2025: Injection moved to A05 (from A03 in 2021).
            category: OwaspCategory::A05(),
            kind: CheckKind::Active,
            default_severity: Severity::High,
            description:
                "Sends boundary-breaking payloads per parameter and matches responses \
                 against the corvex-core DBMS error signature bank."
                    .to_string(),        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Baseline — errors already present without any injection get
        // suppressed so we don't flag pre-existing error pages.
        let baseline_errors: HashSet<String> = match ctx.client.send(&target.request).await {
            Ok(r) => error_matches(&r.body_str())
                .into_iter()
                .map(|m| m.description.to_string())
                .collect(),
            Err(_) => HashSet::new(),
        };

        let mut seen: HashSet<String> = HashSet::new();
        for probe in sqli_error_probes() {
            for (param, mutated) in with_param_payload(&target.request, probe) {
                if seen.contains(&param) {
                    continue;
                }
                let resp = match ctx.client.send(&mutated).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let matches = error_matches(&resp.body_str());
                let new_matches: Vec<_> = matches
                    .into_iter()
                    .filter(|m| !baseline_errors.contains(m.description))
                    .collect();
                if new_matches.is_empty() {
                    continue;
                }
                let dbms_names: Vec<String> = new_matches
                    .iter()
                    .map(|m| format!("{:?}", m.dbms))
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                seen.insert(param.clone());
                findings.push(
                    Finding::new(
                        "error-based-sqli",
                        target.id,
                        Severity::High,
                        format!("SQL error in `{param}`"),
                    )
                    .with_description(
                        "The parameter value altered the server's SQL query in a way that \
                         surfaced a database error. This almost always indicates that \
                         attacker-controlled input reaches the query unescaped."
                            .to_string(),                    )
                    .with_evidence(json!({
                        "param": param,
                        "payload": probe,
                        "dbms": dbms_names,
                        "signatures": new_matches
                            .iter()
                            .map(|m| m.description.to_string())
                            .collect::<Vec<_>>(),
                    })),
                );
            }
        }
        findings
    }
}
