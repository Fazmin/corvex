//! Check traits and descriptor metadata.
//!
//! Two traits exist on purpose — passive checks must stay in the
//! request hot path without paying tasks-spawning overhead, while
//! active checks need async because they send their own requests.

use std::sync::Arc;

use async_trait::async_trait;
use corvex_core::http::client::HttpClient;
use corvex_proxy::Exchange;
use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Severity};

/// OWASP category assignment. The value is a code string from the
/// active taxonomy (e.g. `"A01"`) — metadata (label, description,
/// reference URL) is resolved on demand via [`corvex_intel::owasp`].
/// Stored as a string so yearly taxonomy updates require no changes
/// to code or persisted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OwaspCategory(pub String);

impl OwaspCategory {
    /// Build a category from its code. Accepts anything; validation
    /// happens when the descriptor is rendered to the UI — an
    /// unknown code shows as "Uncategorised" rather than breaking
    /// compilation. This keeps old findings readable after a
    /// taxonomy swap.
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }

    pub fn code(&self) -> &str {
        &self.0
    }

    /// Resolve the display label from the default taxonomy.
    pub fn label(&self) -> String {
        corvex_intel::owasp::label_for(&self.0)
    }
}

// Short constructors for every code in the 2021 taxonomy — used by
// the coded checks. Constants rather than enum variants so adding a
// new code from a refreshed taxonomy YAML (e.g. "A11") doesn't need
// a source change.
macro_rules! owasp_codes {
    ($($name:ident = $code:literal),* $(,)?) => {
        impl OwaspCategory {
            $(
                #[allow(non_snake_case)]
                pub fn $name() -> Self { Self::new($code) }
            )*
        }
    }
}

owasp_codes! {
    A01 = "A01",
    A02 = "A02",
    A03 = "A03",
    A04 = "A04",
    A05 = "A05",
    A06 = "A06",
    A07 = "A07",
    A08 = "A08",
    A09 = "A09",
    A10 = "A10",
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    Passive,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckDescriptor {
    /// Stable id stored alongside findings in the DB.
    pub id: String,
    pub name: String,
    pub category: OwaspCategory,
    pub kind: CheckKind,
    pub default_severity: Severity,
    pub description: String,
}

/// Context passed to active checks — gives them an HTTP client and a
/// way to emit findings.
pub struct CheckCtx {
    pub client: Arc<HttpClient>,
    /// Live CSRF token store. Active checks that build their own
    /// outbound probe requests (XSS, SQLi, Open Redirect) call
    /// `apply_to_request` on the request before sending so token-
    /// rotating apps don't 419 every probe — see
    /// `corvex_proxy::CsrfStore::apply_to_request`.
    /// `None` means "don't apply" (the test harness uses this so
    /// fixtures don't depend on a populated store).
    pub csrf: Option<Arc<corvex_proxy::CsrfStore>>,
}

impl CheckCtx {
    /// Convenience: splice fresh CSRF tokens into a request the
    /// active check is about to send. No-op when no store is
    /// attached. Returns the rule ids that fired so the check can
    /// decide whether to tag the resulting finding.
    pub fn apply_csrf(
        &self,
        request: &mut corvex_core::http::request::Request,
    ) -> Vec<String> {
        match self.csrf.as_ref() {
            Some(store) => store.apply_to_request(request),
            None => Vec::new(),
        }
    }

    /// Send a request through the shared HTTP client, splicing fresh
    /// CSRF tokens into the request beforehand when a store is
    /// attached. Drop-in replacement for `ctx.client.send(&req)` —
    /// every active check that builds its own probe should use this
    /// so token-rotating apps don't reject every probe.
    pub async fn send_with_csrf(
        &self,
        request: &corvex_core::http::request::Request,
    ) -> corvex_core::error::Result<corvex_core::http::response::Response> {
        if self.csrf.is_some() {
            let mut spliced = request.clone();
            self.apply_csrf(&mut spliced);
            self.client.send(&spliced).await
        } else {
            self.client.send(request).await
        }
    }
}

/// Synchronous per-exchange inspection. Called from the proxy hot
/// path once per in-scope exchange. Keep the work cheap — regex scans,
/// header lookups. Long-running logic belongs in an active check.
pub trait PassiveCheck: Send + Sync {
    fn descriptor(&self) -> CheckDescriptor;
    fn inspect(&self, exchange: &Exchange) -> Vec<Finding>;
}

/// On-demand probe that may send requests upstream.
#[async_trait]
pub trait ActiveCheck: Send + Sync {
    fn descriptor(&self) -> CheckDescriptor;
    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding>;
}
