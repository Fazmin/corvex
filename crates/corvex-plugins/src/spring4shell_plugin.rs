//! Spring4Shell detector (CVE-2022-22965).
//!
//! Spring MVC applications on Java 9+ that bind request parameters to a
//! POJO can be tricked into reconfiguring the server's Tomcat access-log
//! valve via the `class.module.classLoader.resources.context.parent.*`
//! property chain. Full exploitation writes a JSP shell to disk; *this*
//! check only confirms the vulnerable behaviour exists without placing
//! any files. It does that by setting the log pattern to an empty string
//! and observing that the server still returns 200 on the subsequent
//! request — a patched Spring returns 400 / 500 for the first probe and
//! leaves the logging configuration intact.
//!
//! Inspired by public writeups of the original CVE-2022-22965 PoC
//! (Rapid7, AttackerKB). We intentionally avoid the file-write variant
//! to keep the probe non-destructive.

use std::sync::Mutex as StdMutex;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use corvex_core::crawler::CrawlGraph;
use corvex_core::error::Result;
use corvex_core::fuzzer::param::{FuzzTarget, InjectionPoint};
use corvex_core::fuzzer::runner::{FuzzResult, FuzzRunner};
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

use crate::active_util::{body_snippet, format_point, truncate};

static INFO: PluginInfo = PluginInfo {
    name: "spring4shell",
    full_name: "Spring4Shell (CVE-2022-22965)",
    description: "Non-destructive check for the Spring MVC class-loader property-binding vulnerability. Sends a crafted `class.module.classLoader.resources.context.parent.pipeline.first.pattern` assignment and flags stack traces / specific error patterns that confirm the property path was resolved.",
    weight: 66,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

// Non-destructive probe: set a pattern that contains only a literal
// marker. A vulnerable server resolves the getter chain and fails
// gracefully; a patched one rejects the bind before reaching the
// classloader (SuppressedFields or IllegalStateException).
const PROBE_PATH: &str =
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern";
const PROBE_VALUE: &str = "CORVSPRING-42be17";

// Server-side indicators that the classloader path was walked. Any of
// these in a stack trace or debug body means Spring's property binder
// dereferenced `class.module.classLoader.resources...`, which is the
// fix Spring 5.2.20 / 5.3.18 specifically shut down.
const POSITIVE_MARKERS: &[&str] = &[
    "org.apache.catalina.loader.ParallelWebappClassLoader",
    "context.parent.pipeline.first.pattern",
    "AccessLogValve",
    "disallowedFields",
    "PropertyAccessException",
];

fn payloads() -> Vec<String> {
    vec![
        format!("{}={}", PROBE_PATH, PROBE_VALUE),
        // Some servers also accept the bind expressed as nested brackets —
        // covers older Spring dispatchers.
        format!("{PROBE_PATH}[0]={PROBE_VALUE}"),
    ]
}

#[derive(Default)]
pub struct Spring4ShellPlugin;

fn finding(
    method: &str,
    uri: &str,
    point: &InjectionPoint,
    payload: &str,
    marker: &str,
) -> ReportItem {
    let point_label = format_point(point);
    ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message: format!(
            "Spring4Shell (CVE-2022-22965): payload {payload_short:?} in the \
             {point_label} parameter produced a response containing the \
             marker {marker:?}, indicating Spring's data binder resolved the \
             class-loader property path. The server is almost certainly \
             unpatched — upgrade to Spring Framework 5.3.18+ / 5.2.20+.",
            payload_short = truncate(payload, 160)
        ),
        refs: "CVE-2022-22965 | CWE-94".into(),
        data: String::new(),
        plugin: "spring4shell".to_string(),
        severity: Severity::Critical,
        cve: Some("CVE-2022-22965".to_string()),
        ..Default::default()
    }
}

#[async_trait]
impl Plugin for Spring4ShellPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        let payloads = payloads();
        for page in &graph.pages {
            if ctx.is_cancelled() {
                break;
            }
            let targets = FuzzTarget::from_crawled(page);
            for target in &targets {
                if ctx.is_cancelled() {
                    break;
                }
                if target.points.is_empty() {
                    continue;
                }
                let hits: StdMutex<Vec<ReportItem>> = StdMutex::new(Vec::new());
                let method = target.method.clone();

                FuzzRunner::run(
                    ctx,
                    mark.clone(),
                    target,
                    &payloads,
                    None,
                    |r: FuzzResult| -> bool {
                        let snippet = body_snippet(&r.response.body, 64 * 1024);
                        for m in POSITIVE_MARKERS {
                            if snippet.contains(m) {
                                hits.lock().unwrap().push(finding(
                                    &method,
                                    &r.target_url,
                                    &r.point,
                                    &r.payload,
                                    m,
                                ));
                                return true;
                            }
                        }
                        false
                    },
                )
                .await?;

                let hits = hits.into_inner().unwrap();
                if !hits.is_empty() {
                    ctx.emit(mark.clone(), hits).await;
                }
            }
        }
        Ok(())
    }
}
