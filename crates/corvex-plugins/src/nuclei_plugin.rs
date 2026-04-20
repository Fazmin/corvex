//! Nuclei-template scan engine, wired into the `Active` hook.
//!
//! Lazily loads templates from `program/databases/nuclei/` on first run
//! and from the user's cache dir if the optional Tier-2 extras have been
//! downloaded. Emits one finding per matched template, enriched with
//! VulnDB data when a CVE classification is present.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use once_cell::sync::OnceCell;
use tokio::sync::Mutex;

use corvex_core::crawler::CrawlGraph;
use corvex_core::error::Result;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

use corvex_nuclei::attribution;
use corvex_nuclei::overlap::OverlapMap;
use corvex_nuclei::schema::Severity as NucleiSeverity;
use corvex_nuclei::{Executor, TemplateStore};

static INFO: PluginInfo = PluginInfo {
    name: "nuclei",
    full_name: "Nuclei templates",
    description: "Runs community-maintained Nuclei vulnerability templates (MIT, ProjectDiscovery) against every crawled origin.",
    weight: 70,
    default: false,
    extra: true,
    hooks: &[HookKind::Active],
};

#[derive(Default)]
pub struct NucleiPlugin {
    store: OnceCell<Arc<TemplateStore>>,
    overlap: OnceCell<Arc<OverlapMap>>,
}

#[async_trait]
impl Plugin for NucleiPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        if !config_enabled(ctx) {
            return Ok(());
        }

        let store = self.store.get_or_init(|| Arc::new(load_store(ctx)));
        if store.is_empty() {
            tracing::info!(
                target: "nuclei",
                "no templates loaded — skipping (check program/databases/nuclei/)"
            );
            return Ok(());
        }
        let overlap = self
            .overlap
            .get_or_init(|| Arc::new(load_overlap(ctx)));

        let severities = parse_severity_filter(ctx);
        let tag_include = parse_list(ctx, "nuclei.tag_filter");
        let tag_exclude = parse_list(ctx, "nuclei.tag_exclude");

        let enabled_names: HashSet<&str> = ctx
            .plugins
            .all()
            .iter()
            .map(|p| p.info().name)
            .collect();
        let skip_ids = overlap.skip_for_enabled(&enabled_names);

        let templates: Vec<_> = store
            .filter(&severities, &tag_include, &tag_exclude)
            .into_iter()
            .filter(|t| !skip_ids.contains(&t.id))
            .collect();

        if templates.is_empty() {
            return Ok(());
        }

        let origins = distinct_origins(&graph);
        if origins.is_empty() {
            return Ok(());
        }

        let executor = Executor::new(ctx.http.clone(), ctx.request_sem.clone());

        tracing::info!(
            target: "nuclei",
            "running {} templates × {} origins",
            templates.len(),
            origins.len()
        );

        let mut reported_cves: HashSet<(String, String)> = HashSet::new();

        for origin in &origins {
            if ctx.is_cancelled() {
                break;
            }
            for tpl in &templates {
                if ctx.is_cancelled() {
                    break;
                }
                let hits = executor.run(tpl, origin).await;
                if hits.is_empty() {
                    continue;
                }
                let mut items: Vec<ReportItem> = Vec::with_capacity(hits.len());
                for hit in hits {
                    let mut item = attribution::report_item(tpl, &hit);
                    // VulnDB enrichment: fold CVSS/EPSS/description into
                    // the single finding rather than emit both.
                    let cve_opt = item.cve.clone();
                    if let (Some(cve), Some(vulndb)) = (cve_opt.as_ref(), ctx.vulndb.as_ref())
                    {
                        enrich_with_vulndb(&mut item, vulndb, cve);
                        if !reported_cves.insert((origin.clone(), cve.clone())) {
                            continue;
                        }
                    }
                    items.push(item);
                }
                if !items.is_empty() {
                    ctx.emit(mark.clone(), items).await;
                }
            }
        }
        Ok(())
    }
}

fn config_enabled(ctx: &ScanCtx) -> bool {
    matches!(
        ctx.cfg.get("nuclei.enabled").unwrap_or("false"),
        "true" | "1" | "yes" | "on"
    )
}

fn parse_severity_filter(ctx: &ScanCtx) -> Vec<NucleiSeverity> {
    let raw = ctx
        .cfg
        .get("nuclei.severity_filter")
        .unwrap_or("critical,high");
    raw.split([',', ' '])
        .filter_map(|s| match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(NucleiSeverity::Critical),
            "high" => Some(NucleiSeverity::High),
            "medium" => Some(NucleiSeverity::Medium),
            "low" => Some(NucleiSeverity::Low),
            "info" => Some(NucleiSeverity::Info),
            "" => None,
            _ => None,
        })
        .collect()
}

fn parse_list(ctx: &ScanCtx, key: &str) -> Vec<String> {
    ctx.cfg
        .get(key)
        .unwrap_or("")
        .split([',', ' '])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn load_store(ctx: &ScanCtx) -> TemplateStore {
    let mut store = TemplateStore::new();
    for root in bundled_roots() {
        if let Err(e) = store.load_dir(&root) {
            tracing::warn!(target: "nuclei", "load {}: {}", root.display(), e);
        }
    }
    if matches!(
        ctx.cfg.get("nuclei.use_downloaded_extras").unwrap_or("true"),
        "true" | "1" | "yes" | "on"
    ) {
        for root in extras_roots() {
            if let Err(e) = store.load_dir(&root) {
                tracing::warn!(target: "nuclei", "load extras {}: {}", root.display(), e);
            }
        }
    }
    let counts = store.counts();
    tracing::info!(
        target: "nuclei",
        "loaded {} supported, {} skipped from {} root(s)",
        counts.supported,
        counts.skipped,
        store.roots.len()
    );
    store
}

fn load_overlap(_ctx: &ScanCtx) -> OverlapMap {
    for root in bundled_roots() {
        let p = root.join("overlap.toml");
        if p.exists() {
            match OverlapMap::load(&p) {
                Ok(m) => return m,
                Err(e) => {
                    tracing::warn!(target: "nuclei", "overlap {}: {}", p.display(), e)
                }
            }
        }
    }
    OverlapMap::default()
}

/// Candidate filesystem locations for the bundled Tier-1 templates. We
/// check CWD-relative first (dev runs), then next-to-the-exe (packaged
/// builds). The first existing directory wins; a missing path is not an
/// error — the store will simply contain nothing.
fn bundled_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    roots.push(cwd.join("program").join("databases").join("nuclei"));
    roots.push(PathBuf::from("program").join("databases").join("nuclei"));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            roots.push(parent.join("program").join("databases").join("nuclei"));
            roots.push(parent.join("databases").join("nuclei"));
        }
    }
    roots.retain(|p| p.exists());
    roots
}

/// Tier-2 extras cache — populated by the UI's "Expand coverage" button.
fn extras_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(data) = dirs_data_dir() {
        roots.push(data.join("corvex").join("nuclei-templates"));
    }
    roots.retain(|p| p.exists());
    roots
}

fn dirs_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join(".local").join("share"))
            })
    }
}

fn distinct_origins(graph: &CrawlGraph) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for page in &graph.pages {
        if let Some(origin) = origin_of(&page.url) {
            if seen.insert(origin.clone()) {
                out.push(origin);
            }
        }
    }
    out
}

fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let scheme = u.scheme();
    let host = u.host_str()?;
    match u.port() {
        Some(p) => Some(format!("{scheme}://{host}:{p}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

fn enrich_with_vulndb(
    item: &mut ReportItem,
    vulndb: &Arc<corvex_core::vulndb::VulnDb>,
    cve: &str,
) {
    if let Ok(Some(rec)) = vulndb.get_cve(cve) {
        if item.cvss.is_none() {
            item.cvss = rec.cvss_v31_score;
        }
        let desc = rec.description;
        if !desc.is_empty()
            && !item.message.contains(&desc[..desc.len().min(40)])
        {
            item.message.push_str(" — ");
            item.message.push_str(&truncate(&desc, 200));
        }
    }
    if item.epss_score.is_none() {
        if let Ok(Some(score)) = vulndb.get_epss(cve) {
            item.epss_score = Some(score.score);
            item.epss_percentile = Some(score.percentile);
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_filter_parses_defaults() {
        let raw = "critical,high";
        let parsed: Vec<_> = raw
            .split(',')
            .filter_map(|s| match s.trim().to_ascii_lowercase().as_str() {
                "critical" => Some(NucleiSeverity::Critical),
                "high" => Some(NucleiSeverity::High),
                _ => None,
            })
            .collect();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn origin_strips_path() {
        assert_eq!(
            origin_of("https://example.com:8443/a/b?c=1"),
            Some("https://example.com:8443".to_string())
        );
    }
}
