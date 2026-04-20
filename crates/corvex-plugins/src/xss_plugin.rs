//! Reflected XSS detector.
//!
//! Injects a per-scan canary token (plus several context-breaking variants)
//! into every query / body / cookie injection point and checks whether the
//! response body echoes the raw payload. A naive substring match on a
//! 15-character uppercase-digit token has near-zero false positives: a
//! baseline page is overwhelmingly unlikely to contain the string by
//! coincidence.
//!
//! Runs during the Active hook. Response-only detection — no DOM
//! execution, no headless browser, no cross-page stored-XSS recheck. Stored
//! XSS, DOM XSS, and execution confirmation remain out of scope.
//!
//! Payload families (all embed the same canary so any body-side match is
//! unambiguous):
//!   * plain canary (text-context reflection)
//!   * attribute-break + svg/onload
//!   * classic script-tag reflection
//!   * single-quote break + img onerror
//!   * double-quoted canary

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

use crate::active_util::{canary, format_point, truncate};

static INFO: PluginInfo = PluginInfo {
    name: "xss_reflected",
    full_name: "Reflected Cross-Site Scripting",
    description: "Injects unique canary markers into query / body / cookie parameters and flags responses that echo the raw payload. Text-context, attribute-context, and tag-context variants.",
    weight: 52,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

#[derive(Default)]
pub struct XssPlugin;

fn payloads(token: &str) -> Vec<String> {
    vec![
        token.to_string(),
        format!("\"><svg/onload={}>", token),
        format!("<script>{}</script>", token),
        format!("'><img src=x onerror={}>", token),
        format!("\"{}\"", token),
    ]
}

fn finding(
    method: &str,
    uri: &str,
    point: &InjectionPoint,
    payload: &str,
) -> ReportItem {
    let point_label = format_point(point);
    ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message: format!(
            "Reflected XSS: the {point_label} parameter echoed the canary payload \
             {payload_short:?} into the response body without escaping. An attacker \
             controlling this input can execute arbitrary JavaScript in the \
             victim's browser.",
            payload_short = truncate(payload, 120)
        ),
        refs: "CWE-79".into(),
        data: String::new(),
        plugin: "xss_reflected".to_string(),
        severity: Severity::High,
        ..Default::default()
    }
}

#[async_trait]
impl Plugin for XssPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        let token = canary("CORVXSS");
        let payloads = payloads(&token);

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

                // Buffer hits for this target; FuzzRunner's detector callback
                // is sync so we can't `ctx.emit` from inside it.
                let hits: StdMutex<Vec<ReportItem>> = StdMutex::new(Vec::new());
                let method = target.method.clone();

                FuzzRunner::run(
                    ctx,
                    mark.clone(),
                    target,
                    &payloads,
                    None,
                    |r: FuzzResult| -> bool {
                        let body = match std::str::from_utf8(&r.response.body) {
                            Ok(s) => s,
                            Err(_) => return false,
                        };
                        if body.contains(&token) {
                            hits.lock().unwrap().push(finding(
                                &method,
                                &r.target_url,
                                &r.point,
                                &r.payload,
                            ));
                            // One hit per payload/point combination is
                            // enough — stop iterating remaining variants
                            // on this injection point.
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
