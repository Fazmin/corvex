//! Open-redirect detector.
//!
//! Injects attacker-controlled URLs into every query / body / cookie
//! parameter and flags responses whose `Location` header reflects the
//! injected URL (or a single-slash / path-relative variant of it). A
//! server that redirects to whatever a query parameter asks for gives
//! phishing campaigns a trusted-domain hop.
//!
//! The external host is a known-safe sentinel so we never actually push
//! a victim anywhere real: the redirect destination never gets fetched
//! by Corvex, we only check what the *server* decided to send back.

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

use crate::active_util::{format_point, truncate};

static INFO: PluginInfo = PluginInfo {
    name: "open_redirect",
    full_name: "Open Redirect",
    description: "Injects external URLs into redirect parameters and flags any server that reflects the attacker-controlled destination into its Location header.",
    weight: 54,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

const SENTINEL_HOST: &str = "corvex-probe.invalid";

fn payloads() -> Vec<String> {
    vec![
        format!("https://{}/", SENTINEL_HOST),
        format!("http://{}/", SENTINEL_HOST),
        format!("//{}/", SENTINEL_HOST),
        format!("/\\{}/", SENTINEL_HOST),
        format!("https:{}/", SENTINEL_HOST),
    ]
}

#[derive(Default)]
pub struct OpenRedirectPlugin;

fn header_value<'a>(headers: &'a indexmap::IndexMap<String, String>, name: &str) -> Option<&'a str> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            return Some(v);
        }
    }
    None
}

fn finding(
    method: &str,
    uri: &str,
    point: &InjectionPoint,
    payload: &str,
    location: &str,
) -> ReportItem {
    let point_label = format_point(point);
    ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message: format!(
            "Open redirect: the {point_label} parameter controls the response \
             Location header. Sending {payload_short:?} redirected the client \
             to {loc_short:?}. An attacker can use this to phish users with a \
             trusted first-hop.",
            payload_short = truncate(payload, 120),
            loc_short = truncate(location, 160),
        ),
        refs: "CWE-601".into(),
        data: String::new(),
        plugin: "open_redirect".to_string(),
        severity: Severity::Medium,
        ..Default::default()
    }
}

#[async_trait]
impl Plugin for OpenRedirectPlugin {
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
                        if !matches!(r.response.status, 300..=399) {
                            return false;
                        }
                        let Some(loc) = header_value(&r.response.headers, "Location")
                        else {
                            return false;
                        };
                        // Any appearance of our sentinel host in the Location
                        // header means the server trusted attacker input when
                        // building its redirect target.
                        if loc.contains(SENTINEL_HOST) {
                            hits.lock().unwrap().push(finding(
                                &method,
                                &r.target_url,
                                &r.point,
                                &r.payload,
                                loc,
                            ));
                            return true;
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
