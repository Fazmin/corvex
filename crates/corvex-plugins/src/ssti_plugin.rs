//! Server-Side Template Injection detector.
//!
//! Injects arithmetic expressions in the syntax of common template
//! engines and checks whether the response body contains the *evaluated*
//! result. The arithmetic is deliberately chosen so the output is a
//! specific non-input integer — seeing "6049617" in the response when
//! the input was "{{2467*2451}}" is a very strong signal that the
//! server evaluated the expression.
//!
//! Covered syntaxes:
//!   * Jinja2 / Twig / Nunjucks     — `{{expr}}`
//!   * Smarty / FreeMarker          — `{expr}` / `${expr}`
//!   * Mako                         — `<%= expr %>`
//!   * Thymeleaf                    — `*{expr}` / `${expr}`
//!   * ERB / EJS                    — `<%= expr %>` (same as Mako)
//!   * Spring Expression            — `#{expr}`

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
    name: "ssti",
    full_name: "Server-Side Template Injection",
    description: "Injects arithmetic expressions in the syntax of common template engines (Jinja2, Twig, Smarty, FreeMarker, Mako, Thymeleaf, ERB, Spring EL) and detects evaluation when the evaluated integer result appears in the response body.",
    weight: 62,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

// Two independent operand pairs — using two reduces the already-tiny
// chance the same digits appear in the baseline response by coincidence.
// Values are odd 4-digit primes so the product is a 7-digit non-round
// number that's unlikely to show up elsewhere.
const OP1_A: u32 = 2467;
const OP1_B: u32 = 2451;
const OP2_A: u32 = 3079;
const OP2_B: u32 = 2677;

fn payloads() -> Vec<(String, u64)> {
    let p1 = (OP1_A as u64) * (OP1_B as u64);
    let p2 = (OP2_A as u64) * (OP2_B as u64);
    let mut out: Vec<(String, u64)> = Vec::new();
    for (a, b, product) in [(OP1_A, OP1_B, p1), (OP2_A, OP2_B, p2)] {
        out.push((format!("{{{{{a}*{b}}}}}"), product));        // Jinja2/Twig
        out.push((format!("${{{a}*{b}}}"), product));            // FreeMarker/Thymeleaf
        out.push((format!("{{{a}*{b}}}"), product));             // Smarty
        out.push((format!("<%= {a} * {b} %>"), product));        // Mako/ERB
        out.push((format!("#{{{a}*{b}}}"), product));            // Spring EL
        out.push((format!("*{{{a}*{b}}}"), product));            // Thymeleaf-select
    }
    out
}

#[derive(Default)]
pub struct SstiPlugin;

fn finding(
    method: &str,
    uri: &str,
    point: &InjectionPoint,
    payload: &str,
    product: u64,
) -> ReportItem {
    let point_label = format_point(point);
    ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message: format!(
            "Server-Side Template Injection: payload {payload_short:?} in the \
             {point_label} parameter was evaluated — the response body contains \
             the computed value {product}. The backend renders user input as \
             template syntax, which typically escalates to RCE.",
            payload_short = truncate(payload, 160)
        ),
        refs: "CWE-1336".into(),
        data: String::new(),
        plugin: "ssti".to_string(),
        severity: Severity::Critical,
        ..Default::default()
    }
}

#[async_trait]
impl Plugin for SstiPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        let table = payloads();
        let payload_list: Vec<String> = table.iter().map(|(p, _)| p.clone()).collect();
        let expected: std::collections::HashMap<String, u64> = table
            .iter()
            .map(|(p, v)| (p.clone(), *v))
            .collect();

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
                    &payload_list,
                    None,
                    |r: FuzzResult| -> bool {
                        let product = match expected.get(&r.payload) {
                            Some(v) => *v,
                            None => return false,
                        };
                        let needle = product.to_string();
                        // Skip if our literal payload is also reflected —
                        // the engine clearly didn't evaluate it, it just
                        // echoed it, and the product integer doesn't
                        // appear in a static echo.
                        let snippet = body_snippet(&r.response.body, 64 * 1024);
                        if snippet.contains(&r.payload) {
                            return false;
                        }
                        if snippet.contains(&needle) {
                            hits.lock().unwrap().push(finding(
                                &method,
                                &r.target_url,
                                &r.point,
                                &r.payload,
                                product,
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
