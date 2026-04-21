//! Nuclei-template passive check.
//!
//! Runs the matcher half of the Nuclei template engine against every
//! captured response whose request path matches the template's path
//! pattern. This is the "offline" half of template execution — we
//! don't send new requests here; the active Nuclei runner lands as a
//! follow-up. The payoff is real: thousands of bundled templates
//! become usable immediately against traffic the user is already
//! capturing through the proxy.

use std::sync::Arc;

use corvex_intel::nuclei_mapping::classify;
use corvex_nuclei::matcher::{combine, evaluate};
use corvex_nuclei::schema::{Severity as TmplSeverity, Template};
use corvex_nuclei::store::TemplateStore;
use corvex_proxy::Exchange;
use serde_json::json;

use crate::check::{CheckDescriptor, CheckKind, OwaspCategory, PassiveCheck};
use crate::finding::{Finding, Severity};

/// Wraps a [`TemplateStore`] and exposes it as a set of per-template
/// passive checks. Constructed once at app start; handed to the
/// registry via [`TemplateChecks::descriptors`] and
/// [`TemplateChecks::inspect`].
pub struct TemplateChecks {
    store: Arc<TemplateStore>,
    /// Only templates whose path pattern is "inspectable offline"
    /// (origin-form, no required mutation beyond variable expansion)
    /// end up here.
    eligible: Vec<EligibleTemplate>,
}

struct EligibleTemplate {
    id: String,
    name: String,
    severity: Severity,
    category: OwaspCategory,
    path_patterns: Vec<String>,
    template: Arc<Template>,
}

impl TemplateChecks {
    pub fn new(store: Arc<TemplateStore>) -> Self {
        let mut eligible = Vec::new();
        for tpl in store.iter() {
            for tpl_req in &tpl.http {
                // Offline evaluation only makes sense when the template
                // has matchers and its path uses the standard
                // `{{BaseURL}}<path>` prefix form — meaning the
                // matcher is meant to run on an unmodified request to
                // the base URL plus a known path.
                if tpl_req.matchers.is_empty() {
                    continue;
                }
                let patterns: Vec<String> = tpl_req
                    .path
                    .iter()
                    .filter_map(|p| base_url_path(p))
                    .collect();
                if patterns.is_empty() {
                    continue;
                }
                eligible.push(EligibleTemplate {
                    id: tpl.id.clone(),
                    name: tpl.info.name.clone(),
                    severity: tmpl_severity_to_finding(tpl.info.severity),
                    category: OwaspCategory::new(classify(&tpl.info.tags, &tpl.id)),
                    path_patterns: patterns,
                    template: Arc::new(tpl.clone()),
                });
                // One eligible entry per template is enough — don't
                // double-count templates with multiple HTTP blocks.
                break;
            }
        }
        Self { store, eligible }
    }

    pub fn store(&self) -> &Arc<TemplateStore> {
        &self.store
    }

    pub fn len(&self) -> usize {
        self.eligible.len()
    }

    pub fn is_empty(&self) -> bool {
        self.eligible.is_empty()
    }

    /// Lower each eligible template into a check descriptor. One
    /// descriptor per template — keeps the UI library honest and the
    /// enable/disable toggles meaningful.
    pub fn descriptors(&self) -> Vec<CheckDescriptor> {
        self.eligible
            .iter()
            .map(|e| CheckDescriptor {
                id: format!("nuclei:{}", e.id),
                name: e.name.clone(),
                category: e.category.clone(),
                kind: CheckKind::Passive,
                default_severity: e.severity,
                description: format!(
                    "Nuclei template — matches {} in the response when the request \
                     path matches `{}`.",
                    e.name,
                    e.path_patterns.join(" | ")
                ),
            })
            .collect()
    }

    /// Run every eligible template against the exchange. Findings
    /// carry the prefixed `nuclei:<id>` check id so the UI can filter
    /// them by library entry.
    pub fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        let Some(response) = &exchange.response else {
            return Vec::new();
        };
        let request_path = split_path(&exchange.request.uri);
        let env = corvex_nuclei::dsl::Environment::new();
        let mut findings = Vec::new();

        for e in &self.eligible {
            if !e.path_patterns.iter().any(|p| paths_equivalent(p, &request_path)) {
                continue;
            }
            let Some(tpl_req) = e.template.http.first() else {
                continue;
            };
            let outcomes: Vec<_> = tpl_req
                .matchers
                .iter()
                .map(|m| evaluate(m, response, &env))
                .collect();
            let combined = combine(&outcomes, tpl_req.matchers_condition);
            if !combined.matched {
                continue;
            }
            let mut finding = Finding::new(
                format!("nuclei:{}", e.id),
                exchange.id,
                e.severity,
                e.name.clone(),
            )
            .with_evidence(json!({
                "template_id": e.id,
                "path_match": request_path,
                "evidence": combined.evidence,
            }));
            if let Some(description) = &e.template.info.description {
                finding = finding.with_description(description.clone());
            }
            findings.push(finding);
        }
        findings
    }
}

/// Adapter that plugs [`TemplateChecks`] into the [`PassiveCheck`]
/// trait so the registry can treat it like any other bundled check.
pub struct NucleiTemplateAdapter {
    pub inner: Arc<TemplateChecks>,
}

impl PassiveCheck for NucleiTemplateAdapter {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "nuclei-templates".into(),
            name: "Nuclei Templates (passive match)".into(),
            // Library-wide default; each template descriptor carries
            // its own classified category. 2025: A03 Software Supply
            // Chain Failures absorbed the 2021 A06 Vulnerable and
            // Outdated Components — most CVE-tagged templates now
            // land here by default.
            category: OwaspCategory::A03(),
            kind: CheckKind::Passive,
            default_severity: Severity::Info,
            description:
                "Evaluates the matcher half of every eligible bundled Nuclei template \
                 against captured responses whose request path matches the template's \
                 base path. Per-template descriptors are surfaced via the registry for \
                 fine-grained enable/disable."
                    .to_string(),
        }
    }

    fn inspect(&self, exchange: &Exchange) -> Vec<Finding> {
        self.inner.inspect(exchange)
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

/// Strip the `{{BaseURL}}` (or equivalent) prefix from a template
/// path. Templates that use dynamic path expressions or raw requests
/// return `None` and fall out of the eligible set.
fn base_url_path(p: &str) -> Option<String> {
    let trimmed = p.trim();
    let stripped = trimmed
        .strip_prefix("{{BaseURL}}")
        .or_else(|| trimmed.strip_prefix("{{RootURL}}"))?;
    let stripped = stripped.trim_start_matches('/');
    let without_query = stripped.split(['?', '#']).next().unwrap_or("");
    // Skip paths that still contain template syntax — we can't match
    // them safely offline without executing the template engine's
    // variable expansion.
    if without_query.contains("{{") {
        return None;
    }
    // Normalise to a leading-slash form for comparison.
    Some(format!("/{without_query}"))
}

fn split_path(uri: &str) -> String {
    uri.split_once('?')
        .map(|(p, _)| p.to_string())
        .unwrap_or_else(|| uri.to_string())
}

fn paths_equivalent(pattern: &str, actual: &str) -> bool {
    // Exact-match today. A later iteration can add prefix-glob
    // semantics once we see false-negative patterns in real traffic.
    pattern.eq_ignore_ascii_case(actual)
}
