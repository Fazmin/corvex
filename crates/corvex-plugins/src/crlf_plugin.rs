//! CRLF-injection / header-splitting detector.
//!
//! Injects an embedded `\r\n<header-name>: <canary>` sequence into every
//! query / body / cookie / header / path parameter, then checks whether
//! that canary header comes back on the response. If a server takes
//! user input and drops it into its own response-header construction
//! without filtering newlines, the canary shows up as a real header.
//!
//! Detection is header-only (no body-side fallback) to avoid false
//! positives from servers that merely echo the newline sequence inside
//! their page body.

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
    name: "crlf",
    full_name: "HTTP Response Header Injection (CRLF)",
    description: "Injects newline sequences carrying a canary header into parameters and flags responses that echo the forged header back. Confirms header-splitting / CRLF-injection vulnerabilities.",
    weight: 56,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

const HEADER_NAME: &str = "X-Corvex-Canary";

fn payloads(token: &str) -> Vec<String> {
    // Mix of raw CRLF, URL-encoded (server may decode once), and
    // doubly-encoded variants — different frameworks normalise input at
    // different layers.
    vec![
        format!("corvex\r\n{HEADER_NAME}: {token}"),
        format!("corvex%0d%0a{HEADER_NAME}:%20{token}"),
        format!("corvex%0D%0A{HEADER_NAME}:%20{token}"),
        format!("corvex%%0d%%0a{HEADER_NAME}:%%20{token}"),
        format!("corvex\n{HEADER_NAME}: {token}"),
    ]
}

#[derive(Default)]
pub struct CrlfPlugin;

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
            "HTTP response-header injection (CRLF): newline characters in the \
             {point_label} parameter were reflected into the response headers \
             as a new header ({HEADER_NAME}). Payload: {payload_short:?}. An \
             attacker can split responses, set malicious cookies, or poison \
             caches.",
            payload_short = truncate(payload, 160)
        ),
        refs: "CWE-113".into(),
        data: String::new(),
        plugin: "crlf".to_string(),
        severity: Severity::High,
        ..Default::default()
    }
}

#[async_trait]
impl Plugin for CrlfPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        let token = canary("CORVCRLF");
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
                let hits: StdMutex<Vec<ReportItem>> = StdMutex::new(Vec::new());
                let method = target.method.clone();

                FuzzRunner::run(
                    ctx,
                    mark.clone(),
                    target,
                    &payloads,
                    None,
                    |r: FuzzResult| -> bool {
                        // Look for our canary header by name in the response.
                        // reqwest normalises header names to lowercase; match
                        // case-insensitively and check the value.
                        let forged = r.response.headers.iter().any(|(k, v)| {
                            k.eq_ignore_ascii_case(HEADER_NAME) && v.contains(&token)
                        });
                        if forged {
                            hits.lock().unwrap().push(finding(
                                &method,
                                &r.target_url,
                                &r.point,
                                &r.payload,
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
