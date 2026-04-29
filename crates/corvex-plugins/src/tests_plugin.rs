//! Core test runner — iterates `db_tests`, fires the requests, evaluates
//! the DSL, emits findings. This is the Rust port of `corvex_tests.plugin`.

use async_trait::async_trait;
use corvex_core::dsl::{self, DslEvaluator};
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use corvex_core::vars;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "tests",
    full_name: "Corvex Tests",
    description: "Execute the db_tests signature database against the target.",
    weight: 99,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

/// Map a tuning category string to a severity level.
/// Tuning categories: 0=File Upload, 1=Interesting Files, 2=Misconfig,
/// 3=Info Disc, 4=XSS/Injection, 5=RFI, 6=DoS, 7=RFR, 8=RCE, 9=SQLi,
/// a=Auth Bypass, b=Software ID, c=Remote Inclusion, d=WebService,
/// e=Admin Console, f=XML Injection.
fn severity_from_tuning(tuning: &str) -> Severity {
    // Pick the highest-severity category present in the tuning string.
    let mut best = Severity::Info;
    for c in tuning.chars() {
        let s = match c {
            '8' => Severity::Critical,                  // RCE
            '9' | '4' | 'f' => Severity::High,          // SQLi, XSS/Injection, XML Injection
            '0' | '5' | '6' | 'a' | 'c' => Severity::High, // File Upload, RFI, DoS, Auth Bypass, Remote Inclusion
            '2' | '7' | 'e' => Severity::Medium,        // Misconfig, RFR, Admin Console
            '1' | '3' | 'd' => Severity::Low,           // Interesting Files, Info Disc, WebService
            'b' => Severity::Info,                       // Software ID
            _ => Severity::Info,
        };
        if s > best {
            best = s;
        }
    }
    best
}

#[derive(Default)]
pub struct TestsPlugin;

#[async_trait]
impl Plugin for TestsPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        // Phase 2d cutover: when the user asks the unified path to own
        // Nikto, this plugin steps aside. The mirror flag --legacy-only
        // would force this plugin to run regardless and is the implicit
        // default already, so it doesn't need a check here.
        if ctx.cli.rules_only {
            tracing::debug!(
                target: "tests_plugin",
                "--rules-only set; skipping (RulesPlugin owns the Nikto path)"
            );
            return Ok(());
        }
        let dbs = ctx.dbs.clone();
        let tuning = ctx.tuning.clone();

        // Snapshot the tests — avoid holding a borrow across awaits.
        let tests = dbs.tests.rows.clone();
        let total = tests.len();
        tracing::info!(target: "tests_plugin", "running {total} tests");

        for row in tests.into_iter() {
            if ctx.is_cancelled() {
                tracing::info!(target: "tests_plugin", "cancelled");
                return Ok(());
            }
            if !tuning.allows(&row.tuning) {
                continue;
            }
            // Parse the DSL. @LFI() tokens need to be expanded to real
            // body/header matchers before the parser sees them.
            let dsl_src = vars::expand_lfi_dsl(&row.dsl, &dbs);
            let dsl_ast = match dsl::parse(&dsl_src) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Expand variables into concrete URI candidates.
            let uris: Vec<String> = {
                let m = mark.lock().await;
                vars::expand_all(&row.uri, &m, &dbs)
            };

            for uri in uris {
                let uri = ctx.evasion.apply(uri);
                let mut req = {
                    let m = mark.lock().await;
                    let method = if row.method.is_empty() {
                        "GET"
                    } else {
                        &row.method
                    };
                    let mut r = Request::new(&m.hostname, m.port, method, &uri);
                    if !row.data.is_empty() {
                        r.body = row.data.clone().into_bytes();
                        r.set_header(
                            "Content-Type",
                            "application/x-www-form-urlencoded",
                        );
                    }
                    if !row.headers.is_empty() {
                        for hdr in row.headers.split('\n') {
                            if let Some((k, v)) = hdr.split_once(':') {
                                r.set_header(k.trim(), v.trim());
                            }
                        }
                    }
                    r.ssl = m.ssl;
                    r
                };

                let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let jar = {
                    let m = mark.lock().await;
                    m.cookie_jar.clone()
                };
                let result = DslEvaluator::eval(&dsl_ast, &resp, &jar);
                if result.matched {
                    let item = ReportItem {
                        corvex_id: row.id.clone(),
                        method: req.method.clone(),
                        uri: req.uri.clone(),
                        message: row.message.clone(),
                        refs: row.references.clone(),
                        data: row.data.clone(),
                        plugin: INFO.name.to_string(),
                        severity: severity_from_tuning(&row.tuning),
                        ..Default::default()
                    };
                    ctx.emit(mark.clone(), vec![item]).await;
                }
            }
        }

        Ok(())
    }
}
