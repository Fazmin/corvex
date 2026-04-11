//! Core test runner — iterates `db_tests`, fires the requests, evaluates
//! the DSL, emits findings. This is the Rust port of `nikto_tests.plugin`.

use async_trait::async_trait;
use nikto_core::dsl::{self, DslEvaluator};
use nikto_core::error::Result;
use nikto_core::http::request::Request;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};
use nikto_core::report::ReportItem;
use nikto_core::scan::ScanCtx;
use nikto_core::target::Mark;
use nikto_core::vars;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "tests",
    full_name: "Nikto Tests",
    description: "Execute the db_tests signature database against the target.",
    weight: 99,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct TestsPlugin;

#[async_trait]
impl Plugin for TestsPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let dbs = ctx.dbs.clone();
        let tuning = ctx.tuning.clone();

        // Snapshot the tests — avoid holding a borrow across awaits.
        let tests = dbs.tests.rows.clone();
        let total = tests.len();
        tracing::info!(target: "tests_plugin", "running {total} tests");

        for row in tests.into_iter() {
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
                        nikto_id: row.id.clone(),
                        method: req.method.clone(),
                        uri: req.uri.clone(),
                        message: row.message.clone(),
                        refs: row.references.clone(),
                        data: row.data.clone(),
                        plugin: INFO.name.to_string(),
                    };
                    ctx.emit(mark.clone(), vec![item]).await;
                }
            }
        }

        Ok(())
    }
}
