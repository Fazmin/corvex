//! Bundled check registry.
//!
//! The registry owns the canonical list of checks and exposes the
//! three entry points the proxy layer needs — describe everything,
//! run all passive checks on an exchange, and run the selected active
//! checks against a target.

use std::sync::Arc;

use corvex_intel::fingerprint::LoadedFingerprint;
use corvex_nuclei::store::TemplateStore;
use corvex_proxy::Exchange;
use futures::future::join_all;

use crate::active::{ErrorBasedSqli, OpenRedirect, ReflectedXss};
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, PassiveCheck};
use crate::finding::Finding;
use crate::passive::{
    InsecureCookies, NucleiTemplateAdapter, SecurityHeaders, StackFingerprint, TemplateChecks,
    VerboseErrors, VersionDisclosure,
};

pub struct CheckRegistry {
    passive: Vec<Arc<dyn PassiveCheck>>,
    active: Vec<Arc<dyn ActiveCheck>>,
    /// Per-template descriptor cache — kept around so the UI library
    /// can render individual template entries grouped by OWASP without
    /// going through the generic `descriptors()` path.
    template_descriptors: Vec<CheckDescriptor>,
}

impl CheckRegistry {
    pub fn new(
        passive: Vec<Arc<dyn PassiveCheck>>,
        active: Vec<Arc<dyn ActiveCheck>>,
    ) -> Self {
        Self {
            passive,
            active,
            template_descriptors: Vec::new(),
        }
    }

    /// Add per-template descriptors from a [`TemplateChecks`]. Each
    /// template becomes its own row in the Checks library so the user
    /// can enable / disable individual rules.
    pub fn with_templates(mut self, templates: Arc<TemplateChecks>) -> Self {
        self.template_descriptors = templates.descriptors();
        self.passive
            .push(Arc::new(NucleiTemplateAdapter { inner: templates }));
        self
    }

    pub fn descriptors(&self) -> Vec<CheckDescriptor> {
        let mut out = Vec::with_capacity(
            self.passive.len() + self.active.len() + self.template_descriptors.len(),
        );
        for c in &self.passive {
            // Skip the compound "nuclei-templates" row — individual
            // template descriptors already expose it in a more useful
            // form.
            let d = c.descriptor();
            if d.id == "nuclei-templates" {
                continue;
            }
            out.push(d);
        }
        for c in &self.active {
            out.push(c.descriptor());
        }
        out.extend(self.template_descriptors.iter().cloned());
        out
    }

    /// Run every passive check against the exchange and collect the
    /// findings. Called synchronously in the listener hot path.
    pub fn run_passive(&self, exchange: &Exchange) -> Vec<Finding> {
        let mut findings = Vec::new();
        for check in &self.passive {
            findings.extend(check.inspect(exchange));
        }
        findings
    }

    /// Run the requested active checks concurrently against `target`.
    /// Unknown ids are silently skipped — the UI already validates
    /// against [`descriptors`].
    pub async fn run_active(
        &self,
        ctx: &CheckCtx,
        target: &Exchange,
        ids: &[String],
    ) -> Vec<Finding> {
        let selected: Vec<Arc<dyn ActiveCheck>> = self
            .active
            .iter()
            .filter(|c| ids.contains(&c.descriptor().id))
            .cloned()
            .collect();
        let futures = selected.into_iter().map(|c| {
            let target = target.clone();
            async move { c.run(ctx, &target).await }
        });
        let results = join_all(futures).await;
        let mut findings = Vec::new();
        for batch in results {
            findings.extend(batch);
        }
        findings
    }
}

/// Default registry — Phase 3A coded checks + Phase 3B stack
/// fingerprint (seed dataset only). Nuclei templates and the vendored
/// Wappalyzer upstream are layered on top by
/// [`registry_with_bundles`] since only the desktop layer knows the
/// app-data paths.
pub fn default_registry() -> CheckRegistry {
    default_registry_with_fingerprint(StackFingerprint::new())
}

fn default_registry_with_fingerprint(fp: StackFingerprint) -> CheckRegistry {
    let passive: Vec<Arc<dyn PassiveCheck>> = vec![
        Arc::new(SecurityHeaders),
        Arc::new(VerboseErrors),
        Arc::new(VersionDisclosure),
        Arc::new(InsecureCookies),
        Arc::new(fp),
    ];
    let active: Vec<Arc<dyn ActiveCheck>> = vec![
        Arc::new(ReflectedXss),
        Arc::new(ErrorBasedSqli),
        Arc::new(OpenRedirect),
    ];
    CheckRegistry::new(passive, active)
}

/// Build a registry with Nuclei-template checks layered on top of the
/// default set. `store` is typically constructed via
/// `corvex_nuclei::store::TemplateStore::load_dir(...)`.
pub fn registry_with_templates(store: Arc<TemplateStore>) -> CheckRegistry {
    let templates = Arc::new(TemplateChecks::new(store));
    default_registry().with_templates(templates)
}

/// Full-bundle registry — Nuclei templates plus the vendored
/// Wappalyzer upstream. `upstream` falls back to empty (seed only)
/// when the user hasn't run the refresh script.
pub fn registry_with_bundles(
    nuclei_store: Arc<TemplateStore>,
    upstream_fingerprints: Arc<Vec<LoadedFingerprint>>,
) -> CheckRegistry {
    let fp = StackFingerprint::with_upstream(upstream_fingerprints);
    let templates = Arc::new(TemplateChecks::new(nuclei_store));
    default_registry_with_fingerprint(fp).with_templates(templates)
}
