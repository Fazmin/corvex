//! Plugin trait + registry. Mirrors Perl Corvex's hook lifecycle.

use crate::crawler::CrawlGraph;
use crate::error::Result;
use crate::http::request::Request;
use crate::http::response::Response;
use crate::report::ReportItem;
use crate::scan::ScanCtx;
use crate::target::Mark;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookKind {
    Start,
    Recon,
    Scan,
    Prefetch,
    Postfetch,
    /// Active fuzzing phase — runs after `Scan`, iterates the crawl
    /// graph instead of static db_tests rows.
    Active,
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: &'static str,
    pub full_name: &'static str,
    pub description: &'static str,
    pub weight: i32,
    pub default: bool,
    pub extra: bool,
    pub hooks: &'static [HookKind],
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn info(&self) -> &'static PluginInfo;

    async fn on_start(&self, _ctx: &ScanCtx, _mark: Arc<Mutex<Mark>>) -> Result<()> {
        Ok(())
    }
    async fn on_recon(&self, _ctx: &ScanCtx, _mark: Arc<Mutex<Mark>>) -> Result<()> {
        Ok(())
    }
    async fn on_scan(&self, _ctx: &ScanCtx, _mark: Arc<Mutex<Mark>>) -> Result<()> {
        Ok(())
    }
    async fn on_prefetch(
        &self,
        _ctx: &ScanCtx,
        _mark: Arc<Mutex<Mark>>,
        _req: &mut Request,
    ) -> Result<()> {
        Ok(())
    }
    async fn on_postfetch(
        &self,
        _ctx: &ScanCtx,
        _mark: Arc<Mutex<Mark>>,
        _req: &Request,
        _res: &Response,
    ) -> Result<Vec<ReportItem>> {
        Ok(Vec::new())
    }

    /// Active fuzzing hook. Receives the full crawl graph so the plugin
    /// can iterate targets + injection points via `FuzzRunner`.
    async fn on_active(
        &self,
        _ctx: &ScanCtx,
        _mark: Arc<Mutex<Mark>>,
        _graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, p: Arc<dyn Plugin>) {
        self.plugins.push(p);
    }

    pub fn all(&self) -> &[Arc<dyn Plugin>] {
        &self.plugins
    }

    /// Plugins registered for a given hook, sorted ascending by weight.
    pub fn for_hook(&self, kind: HookKind) -> Vec<Arc<dyn Plugin>> {
        let mut v: Vec<Arc<dyn Plugin>> = self
            .plugins
            .iter()
            .filter(|p| p.info().hooks.contains(&kind))
            .cloned()
            .collect();
        v.sort_by_key(|p| p.info().weight);
        v
    }

    /// Apply a `-Plugins` selector string to filter the registry in place.
    /// Supports:
    /// * `@@ALL`     — keep every plugin
    /// * `@@NONE`    — drop every plugin (used when only the active
    ///                 fuzzer + crawler should run, with no signature
    ///                 findings; combine with `--active`)
    /// * `@@ACTIVE`  — keep only plugins exposing `HookKind::Active`
    ///                 (xss / sqli / lfi / cmd_injection / open_redirect
    ///                 / crlf / xxe / ssti / spring4shell / nuclei) so a
    ///                 Fuzzing-view run gets its fuzzers without the
    ///                 signature plugin set
    /// * `@@DEFAULT` / `@@EXTRAS` — expand to the configured plugin sets
    /// * comma/semicolon-separated names; prefix with `-` to exclude
    ///
    /// Empty / whitespace-only selectors are a no-op (keep current set).
    pub fn apply_selector(
        &mut self,
        selector: &str,
        default_set: &str,
        extras_set: &str,
    ) {
        if selector.trim().is_empty() {
            return;
        }
        let expanded = expand_macros(selector, default_set, extras_set);

        let mut include: Vec<String> = Vec::new();
        let mut exclude: Vec<String> = Vec::new();
        for tok in expanded.split(|c| c == ';' || c == ',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            if let Some(rest) = tok.strip_prefix('-') {
                // Strip any (...) option block
                let name = rest.split('(').next().unwrap_or(rest).trim().to_string();
                exclude.push(name);
            } else {
                let name = tok.split('(').next().unwrap_or(tok).trim().to_string();
                include.push(name);
            }
        }

        let all = include.iter().any(|n| n == "@@ALL");
        let active_only = include.iter().any(|n| n == "@@ACTIVE");
        self.plugins.retain(|p| {
            let name = p.info().name;
            if exclude.iter().any(|n| n == name) {
                return false;
            }
            if all {
                return true;
            }
            if active_only && p.info().hooks.contains(&HookKind::Active) {
                return true;
            }
            include.iter().any(|n| n == name)
        });
    }
}

fn expand_macros(selector: &str, default_set: &str, extras_set: &str) -> String {
    let mut s = selector.to_string();
    // Repeatedly expand until stable.
    for _ in 0..8 {
        let before = s.clone();
        s = s.replace("@@DEFAULT", default_set);
        s = s.replace("@@EXTRAS", extras_set);
        s = s.replace("@@NONE", "");
        if s == before {
            break;
        }
    }
    s
}

