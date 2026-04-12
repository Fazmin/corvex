//! Scan orchestration — mirrors the top-level loop in corvex.pl.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::cli::Cli;
use crate::config::Config;
use crate::crawler::{self, CrawlGraph};
use crate::db::Databases;
use crate::error::{CorvexError, Result};
use crate::evasion::EvasionSet;
use crate::fourohfour::FourOhFourCache;
use crate::http::request::Request;
use crate::http::HttpClient;
use crate::plugin::{HookKind, PluginRegistry};
use crate::profile;
use crate::report::{ReportItem, ReportSink};
use crate::scope::ScopeFilter;
use crate::state::GlobalState;
use crate::target::{resolve, Mark};
use crate::tuning::TuningFilter;

pub struct ScanCtx {
    pub cfg: Arc<Config>,
    pub cli: Arc<Cli>,
    pub http: Arc<HttpClient>,
    pub plugins: Arc<PluginRegistry>,
    pub reports: Arc<Mutex<Vec<Box<dyn ReportSink>>>>,
    pub state: Arc<GlobalState>,
    pub dbs: Arc<Databases>,
    pub tuning: Arc<TuningFilter>,
    pub evasion: Arc<EvasionSet>,
    pub request_sem: Arc<Semaphore>,
    /// Cancelled by external callers (the Tauri desktop UI) to halt a
    /// scan mid-run. CLI usage leaves this untriggered.
    pub cancel: CancellationToken,
    pub scope: Option<Arc<ScopeFilter>>,
}

impl ScanCtx {
    /// True once something (UI cancel, Ctrl-C, …) flipped `cancel`.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

impl ScanCtx {
    /// Execute a single HTTP request with prefetch/postfetch hooks.
    pub async fn nfetch(
        &self,
        mark: Arc<Mutex<Mark>>,
        req: &mut Request,
    ) -> Result<crate::http::response::Response> {
        if self.is_cancelled() {
            return Err(CorvexError::other("scan cancelled"));
        }
        // Run prefetch hooks
        for plugin in self.plugins.for_hook(HookKind::Prefetch) {
            let _ = plugin
                .on_prefetch(self, mark.clone(), req)
                .await;
        }
        {
            let m = mark.lock().await;
            m.cookie_jar.write_into(req);
            req.ssl = m.ssl;
            req.host = m.hostname.clone();
            req.port = m.port;
        }
        let permit = self.request_sem.acquire().await.unwrap();
        let resp = self.http.send(req).await?;
        drop(permit);
        {
            let mut m = mark.lock().await;
            m.cookie_jar.read_from(&resp);
            if m.banner.is_none() {
                if let Some(s) = resp.header("server") {
                    m.banner = Some(s.to_string());
                }
            }
        }
        // Postfetch hooks emit findings
        for plugin in self.plugins.for_hook(HookKind::Postfetch) {
            if let Ok(items) = plugin
                .on_postfetch(self, mark.clone(), req, &resp)
                .await
            {
                if !items.is_empty() {
                    self.emit(mark.clone(), items).await;
                }
            }
        }
        Ok(resp)
    }

    pub async fn emit(&self, mark: Arc<Mutex<Mark>>, items: Vec<ReportItem>) {
        if items.is_empty() {
            return;
        }
        let m = mark.lock().await;
        let mut reports = self.reports.lock().await;
        for item in &items {
            for sink in reports.iter_mut() {
                let _ = sink.item(&m, item);
            }
            m.counters.incr_vulns();
            self.state.incr_finding();
        }
    }
}

/// Top-level driver. Resolves targets, fetches `/`, runs start/recon/scan
/// hooks, writes reports.
pub async fn run(ctx: Arc<ScanCtx>, mut marks: Vec<Mark>) -> Result<()> {
    // Open reports
    {
        let mut reports = ctx.reports.lock().await;
        for sink in reports.iter_mut() {
            sink.head(&ctx.state)?;
        }
    }

    // Resolve DNS for each target (unless --nolookup).
    for mark in marks.iter_mut() {
        if ctx.cli.nolookup {
            continue;
        }
        match resolve(&mark.hostname).await {
            Ok(ip) => mark.ip = Some(ip),
            Err(e) => {
                mark.test_ok = false;
                mark.errmsg = Some(e.to_string());
            }
        }
    }

    let host_sem = Arc::new(Semaphore::new(ctx.cli.max_concurrent_hosts.max(1)));
    let mut handles = Vec::new();

    for mark in marks {
        let ctx = ctx.clone();
        let host_sem = host_sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = host_sem.acquire().await.unwrap();
            let mark = Arc::new(Mutex::new(mark));
            if let Err(e) = scan_one(ctx.clone(), mark.clone()).await {
                tracing::warn!(target: "scan", "target failed: {e}");
            }
            ctx.state
                .hosts_completed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    // Close reports
    ctx.state.finalize();
    {
        let mut reports = ctx.reports.lock().await;
        for sink in reports.iter_mut() {
            sink.summary(&ctx.state)?;
            sink.close()?;
        }
    }
    Ok(())
}

async fn scan_one(ctx: Arc<ScanCtx>, mark: Arc<Mutex<Mark>>) -> Result<()> {
    {
        let m = mark.lock().await;
        ctx.state
            .total_targets
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !m.test_ok {
            tracing::warn!(target: "scan", "skipping {}: {:?}", m.ident, m.errmsg);
            return Ok(());
        }
    }

    // Initial fetch: GET /
    let mut req = {
        let m = mark.lock().await;
        Request::new(&m.hostname, m.port, "GET", &m.root)
    };
    let init = ctx.http.send(&mut req).await;
    let init = match init {
        Ok(r) => r,
        Err(e) => {
            let mut m = mark.lock().await;
            m.errmsg = Some(e.to_string());
            m.test_ok = false;
            return Ok(());
        }
    };

    // Populate platform/banner/ssl_info/404 baseline
    {
        let mut m = mark.lock().await;
        m.platform = profile::platform_profile(&init);
        if m.banner.is_none() {
            if let Some(s) = init.header("server") {
                m.banner = Some(s.to_string());
            }
        }
        if m.ssl_info.is_none() {
            if let Some(info) = init.tls.clone() {
                m.ssl_info = Some(info);
            }
        }
        m.start_time = SystemTime::now();
        // Seed 404 baseline from a random-path fetch later; for now use /.
    }

    // Report host start
    {
        let m = mark.lock().await;
        let mut reports = ctx.reports.lock().await;
        for sink in reports.iter_mut() {
            sink.host_start(&m)?;
            sink.ssl_info(&m)?;
        }
    }

    // Run start → recon → scan hooks. Cancellation is checked at two
    // granularities: between hook kinds and between individual plugins.
    'hooks: for kind in [HookKind::Start, HookKind::Recon, HookKind::Scan] {
        if ctx.is_cancelled() {
            break 'hooks;
        }
        for plugin in ctx.plugins.for_hook(kind) {
            if ctx.is_cancelled() {
                break 'hooks;
            }
            if let Err(e) = match kind {
                HookKind::Start => plugin.on_start(&ctx, mark.clone()).await,
                HookKind::Recon => plugin.on_recon(&ctx, mark.clone()).await,
                HookKind::Scan => plugin.on_scan(&ctx, mark.clone()).await,
                _ => Ok(()),
            } {
                tracing::warn!(target: "scan", "plugin {} failed: {e}", plugin.info().name);
            }
        }
    }

    // Active phase — crawler + active-fuzzer plugins. Only runs when
    // the caller set a scope (--active or --crawl on the CLI, or
    // the desktop app checked the "Active fuzzing" box).
    if let Some(ref scope) = ctx.scope {
        if !ctx.is_cancelled() {
            let seed = {
                let m = mark.lock().await;
                let scheme = if m.ssl { "https" } else { "http" };
                format!("{scheme}://{}:{}{}", m.hostname, m.port, m.root)
            };
            let depth = ctx.cli.crawl_depth.unwrap_or(3) as usize;
            let max = ctx.cli.max_urls.unwrap_or(500) as usize;
            let graph = match crawler::run(&ctx, mark.clone(), &seed, scope, depth, max).await {
                Ok(g) => Arc::new(g),
                Err(e) => {
                    tracing::warn!(target: "scan", "crawler failed: {e}");
                    Arc::new(CrawlGraph::default())
                }
            };

            for plugin in ctx.plugins.for_hook(HookKind::Active) {
                if ctx.is_cancelled() {
                    break;
                }
                if let Err(e) = plugin.on_active(&ctx, mark.clone(), graph.clone()).await {
                    tracing::warn!(target: "scan", "active plugin {} failed: {e}", plugin.info().name);
                }
            }
        }
    }

    // Report host end
    {
        let m = mark.lock().await;
        let mut reports = ctx.reports.lock().await;
        for sink in reports.iter_mut() {
            sink.host_end(&m)?;
        }
    }
    Ok(())
}

/// Seed a 404 baseline by fetching a guaranteed-missing path.
pub async fn seed_baseline(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    cache: &mut FourOhFourCache,
) -> Result<()> {
    let mut req = {
        let m = mark.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Request::new(
            &m.hostname,
            m.port,
            "GET",
            &format!("/corvex-{now}.htm"),
        )
    };
    let resp = ctx
        .http
        .send(&mut req)
        .await
        .map_err(|e| CorvexError::Http(format!("baseline: {e}")))?;
    cache.seed_baseline(&resp);
    Ok(())
}
