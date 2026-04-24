//! Active Nuclei template execution (A03 — Software Supply Chain).
//!
//! Where [`TemplateChecks`](crate::passive::TemplateChecks) runs only
//! the matcher half of templates against already-captured traffic,
//! this check runs the full Executor — each template fires its own
//! HTTP requests against the target's base URL. That's how bundled
//! templates for path-specific vulnerabilities (WordPress admin
//! endpoints, Jenkins /script, Confluence OGNL, specific CVEs that
//! live on fixed URIs) actually turn into findings.
//!
//! # Default filter
//!
//! Running every template would be many thousands of requests per
//! target. Out of the box the check only fires templates whose
//! severity is Critical or High, or whose tags include any of the
//! `KEV_TAGS` below — CISA Known-Exploited-Vulnerabilities entries
//! and the rare Medium-but-urgent tags ("fileupload", "rce", "auth-
//! bypass"). Users who need a full sweep can set
//! `NUCLEI_ACTIVE_INCLUDE_ALL=1` in the environment before starting
//! the app; the env check is cached at first run.
//!
//! # Request budget
//!
//! The Executor already caps itself at `per_template_request_cap`
//! requests per template. On top of that we bound the total number of
//! templates we'll fire per target at [`MAX_TEMPLATES_PER_TARGET`] —
//! a safety net so a misconfigured run doesn't accidentally launch
//! a 40-minute scan from a single Checks-tab click.

use std::sync::Arc;

use async_trait::async_trait;
use corvex_nuclei::executor::{Executor, Hit};
use corvex_nuclei::schema::{Severity as TmplSeverity, Template};
use corvex_nuclei::store::TemplateStore;
use corvex_proxy::Exchange;
use serde_json::json;
use tokio::sync::Semaphore;

use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

/// Cap on how many templates we'll fire against a single target in
/// one run. Kept conservative so default-filter sweeps stay under
/// ~1,000 HTTP requests per target (assuming each template averages
/// ~3 requests before matching / giving up).
const MAX_TEMPLATES_PER_TARGET: usize = 300;

/// Maximum in-flight HTTP requests across all running templates.
/// Picks a middle ground: enough parallelism to finish in reasonable
/// time, low enough to stay polite against a test target.
const REQUEST_CONCURRENCY: usize = 8;

/// Tag hints that upgrade a Medium-severity template into the default
/// run set. All lowercased; matching is exact substring via
/// `iter().any()`. When the upstream Nuclei catalogue adds a new
/// high-signal tag we want to run by default, extend this list rather
/// than flipping the severity gate wider.
const KEV_TAGS: &[&str] = &[
    "kev",
    "rce",
    "auth-bypass",
    "authbypass",
    "ssrf",
    "sqli",
    "lfi",
    "rfi",
    "xxe",
    "command-injection",
    "fileupload",
    "file-upload",
    "deserialization",
    "takeover",
];

pub struct NucleiActive {
    store: Arc<TemplateStore>,
}

impl NucleiActive {
    pub fn new(store: Arc<TemplateStore>) -> Self {
        Self { store }
    }

    /// Default eligibility filter: Critical / High severity, or any
    /// template whose tags include a `KEV_TAGS` entry.
    fn eligible_templates(&self) -> Vec<&Template> {
        let mut out = Vec::with_capacity(128);
        let include_all = std::env::var("NUCLEI_ACTIVE_INCLUDE_ALL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        for tpl in self.store.iter() {
            if out.len() >= MAX_TEMPLATES_PER_TARGET {
                break;
            }
            // Executor needs at least one HTTP request block —
            // non-HTTP templates are already filtered at load, but a
            // belt-and-braces check protects against parser drift.
            if tpl.http.is_empty() {
                continue;
            }
            if include_all {
                out.push(tpl);
                continue;
            }
            let sev_ok = matches!(
                tpl.info.severity,
                TmplSeverity::Critical | TmplSeverity::High,
            );
            let tag_ok = tpl
                .info
                .tags
                .iter()
                .any(|t| KEV_TAGS.iter().any(|kev| t.eq_ignore_ascii_case(kev)));
            if sev_ok || tag_ok {
                out.push(tpl);
            }
        }
        out
    }
}

#[async_trait]
impl ActiveCheck for NucleiActive {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "nuclei-active".into(),
            name: "Nuclei Templates (active execution)".into(),
            category: OwaspCategory::A03(),
            kind: CheckKind::Active,
            default_severity: Severity::High,
            description: format!(
                "Runs the HTTP-protocol subset of bundled Nuclei templates against the \
                 target's base URL. Default filter: Critical / High severity plus \
                 templates tagged kev / rce / auth-bypass / ssrf / sqli / lfi / rfi / \
                 xxe / command-injection / fileupload / deserialization / takeover. \
                 Set NUCLEI_ACTIVE_INCLUDE_ALL=1 before app startup to fire every \
                 eligible template; hard cap {MAX_TEMPLATES_PER_TARGET} templates per \
                 target regardless."
            ),
        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        let base_url = target_base_url(target);
        let templates = self.eligible_templates();
        if templates.is_empty() {
            return Vec::new();
        }

        let sem = Arc::new(Semaphore::new(REQUEST_CONCURRENCY));
        let executor = Executor::new(ctx.client.clone(), sem);

        let mut findings = Vec::new();
        let mut template_ids_run = Vec::new();

        // Templates are run sequentially — the Executor's own
        // request semaphore handles concurrency within a template,
        // and running two templates in parallel against the same
        // target tends to just add noise without speeding things up.
        for tpl in templates {
            template_ids_run.push(tpl.id.clone());
            let hits: Vec<Hit> = executor.run(tpl, &base_url).await;
            for hit in hits {
                let severity = tmpl_severity_to_finding(tpl.info.severity);
                let mut finding = Finding::new(
                    format!("nuclei-active:{}", hit.template_id),
                    target.id,
                    severity,
                    format!("{} (via nuclei-active)", tpl.info.name),
                )
                .with_evidence(json!({
                    "template_id": hit.template_id,
                    "target_url": hit.target_url,
                    "matched_at": hit.matched_at,
                    "matcher_name": hit.matcher_name,
                    "evidence": hit.evidence,
                    "extracted": hit.extracted,
                    "last_request_method": hit.last_request_method,
                    "last_request_uri": hit.last_request_uri,
                    "last_response_status": hit.last_response_status,
                    "template_tags": tpl.info.tags,
                }));
                if let Some(description) = &tpl.info.description {
                    finding = finding.with_description(description.clone());
                }
                findings.push(finding);
            }
        }

        tracing::debug!(
            target: "checks.nuclei-active",
            "ran {} templates against {base_url}, produced {} findings",
            template_ids_run.len(),
            findings.len(),
        );

        findings
    }
}

fn target_base_url(target: &Exchange) -> String {
    let scheme = if target.request.ssl { "https" } else { "http" };
    let default_port = if target.request.ssl { 443 } else { 80 };
    if target.request.port == default_port {
        format!("{scheme}://{}", target.request.host)
    } else {
        format!(
            "{scheme}://{}:{}",
            target.request.host, target.request.port,
        )
    }
}

fn tmpl_severity_to_finding(s: TmplSeverity) -> Severity {
    match s {
        TmplSeverity::Critical => Severity::Critical,
        TmplSeverity::High => Severity::High,
        TmplSeverity::Medium => Severity::Medium,
        TmplSeverity::Low => Severity::Low,
        TmplSeverity::Info | TmplSeverity::Unknown => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_advertises_active_nuclei_metadata() {
        let store = Arc::new(TemplateStore::new());
        let check = NucleiActive::new(store);
        let d = check.descriptor();
        assert_eq!(d.id, "nuclei-active");
        assert_eq!(d.kind, CheckKind::Active);
        assert_eq!(d.category.code(), "A03");
        assert_eq!(d.default_severity, Severity::High);
        assert!(d.description.contains("NUCLEI_ACTIVE_INCLUDE_ALL"));
    }

    #[test]
    fn empty_store_yields_empty_eligibility() {
        let store = Arc::new(TemplateStore::new());
        let check = NucleiActive::new(store);
        assert!(check.eligible_templates().is_empty());
    }

    #[test]
    fn kev_tags_covers_top_severity_classes() {
        for expected in ["rce", "auth-bypass", "ssrf", "sqli", "lfi", "xxe"] {
            assert!(
                KEV_TAGS.iter().any(|t| *t == expected),
                "KEV_TAGS missing `{expected}`"
            );
        }
    }

    #[test]
    fn severity_mapping_covers_every_variant() {
        assert!(matches!(
            tmpl_severity_to_finding(TmplSeverity::Critical),
            Severity::Critical
        ));
        assert!(matches!(
            tmpl_severity_to_finding(TmplSeverity::High),
            Severity::High
        ));
        assert!(matches!(
            tmpl_severity_to_finding(TmplSeverity::Medium),
            Severity::Medium
        ));
        assert!(matches!(
            tmpl_severity_to_finding(TmplSeverity::Low),
            Severity::Low
        ));
        assert!(matches!(
            tmpl_severity_to_finding(TmplSeverity::Info),
            Severity::Info
        ));
        assert!(matches!(
            tmpl_severity_to_finding(TmplSeverity::Unknown),
            Severity::Info
        ));
    }
}
