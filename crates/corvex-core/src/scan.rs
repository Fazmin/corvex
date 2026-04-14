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
use crate::portscan;
use crate::profile;
use crate::report::{ReportItem, ReportSink, Severity};
use crate::scope::ScopeFilter;
use crate::state::GlobalState;
use crate::target::{resolve, Mark};
use crate::tuning::TuningFilter;
use crate::vulndb::VulnDb;

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
    /// Optional vulnerability database for SCA lookups.
    pub vulndb: Option<Arc<VulnDb>>,
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
                tracing::error!(
                    target: "scan",
                    "DNS resolution failed for {}: {}",
                    mark.hostname,
                    e
                );
                mark.test_ok = false;
                mark.errmsg = Some(e.to_string());
            }
        }
    }

    // ---- Port scanning pre-phase ----
    if ctx.cli.portscan {
        let mut new_marks: Vec<Mark> = Vec::new();
        let port_list = portscan::parse_port_range(&ctx.cli.ports_range);
        tracing::info!(
            target: "scan",
            "port scanning {} ports on {} hosts (threads: {})",
            port_list.len(),
            marks.len(),
            ctx.cli.portscan_threads,
        );

        for mark in &marks {
            if !mark.test_ok {
                continue;
            }
            let ip = match mark.ip {
                Some(ip) => ip,
                None => continue,
            };

            let result = portscan::tcp_scan(
                ip,
                &mark.hostname,
                &port_list,
                ctx.cli.portscan_threads,
                3000, // 3s connect timeout
                ctx.cli.service_detect,
            )
            .await;

            ctx.state.ports_scanned.fetch_add(
                port_list.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            ctx.state.open_ports_found.fetch_add(
                result.open_ports.len() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );

            tracing::info!(
                target: "scan",
                "found {} open ports on {}",
                result.open_ports.len(),
                mark.hostname,
            );

            // For each discovered HTTP/HTTPS port that isn't already a target,
            // create a new Mark.
            for op in &result.open_ports {
                if op.port == mark.port {
                    continue; // Already targeting this port
                }
                if let Some(ref svc) = op.service {
                    if portscan::is_http_service(&svc.name) {
                        let ssl = svc.tls || op.port == 443 || op.port == 8443;
                        let new_mark = Mark::new(
                            format!("{}:{}", mark.hostname, op.port),
                            mark.hostname.clone(),
                            op.port,
                            ssl,
                            "/".to_string(),
                        );
                        new_marks.push(new_mark);
                    }
                }
            }

            // Emit port scan findings
            // Store the result so plugins can use it later
            let mut findings: Vec<ReportItem> = Vec::new();
            for op in &result.open_ports {
                let svc_name = op
                    .service
                    .as_ref()
                    .map(|s| s.name.as_str())
                    .unwrap_or("unknown");
                let banner_str = op
                    .service
                    .as_ref()
                    .map(|s| s.banner.as_str())
                    .unwrap_or("");
                findings.push(ReportItem {
                    corvex_id: format!("PORT-{}", op.port),
                    method: "TCP".into(),
                    uri: format!(":{}", op.port),
                    message: format!(
                        "Open port {}: {} {}",
                        op.port,
                        svc_name,
                        if banner_str.is_empty() {
                            String::new()
                        } else {
                            format!("({})", banner_str.chars().take(80).collect::<String>())
                        }
                    ),
                    refs: String::new(),
                    data: String::new(),
                    plugin: "portscan".to_string(),
                    severity: Severity::Info,
                    ..Default::default()
                });
            }
            if !findings.is_empty() {
                // Create a lightweight Mark just for emitting port scan findings
                let tmp_mark = Mark::new(
                    mark.ident.clone(),
                    mark.hostname.clone(),
                    mark.port,
                    mark.ssl,
                    mark.root.clone(),
                );
                let mark_arc = Arc::new(Mutex::new(tmp_mark));
                ctx.emit(mark_arc, findings).await;
            }
        }

        // Add newly discovered HTTP targets
        if !new_marks.is_empty() {
            tracing::info!(
                target: "scan",
                "port scan discovered {} additional HTTP targets",
                new_marks.len()
            );
            // Resolve DNS for new marks
            for m in new_marks.iter_mut() {
                if let Some(existing) = marks.iter().find(|em| em.hostname == m.hostname) {
                    m.ip = existing.ip;
                }
            }
            marks.extend(new_marks);
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
            tracing::error!(
                target: "scan",
                "initial fetch failed for {}: {}",
                m.ident,
                e
            );
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
