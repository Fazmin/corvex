//! MS10-070 padding oracle probe for ASP.NET.
//!
//! The vulnerable versions respond 200 vs 404 depending on whether the
//! padding on a crafted ScriptResource.axd request validates. Here we send
//! two crafted ciphertext values that differ only in a late byte and
//! compare the status — if they diverge, the server is exploitable.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "ms10_070",
    full_name: "MS10-070",
    description: "ASP.NET Padding Oracle (MS10-070) detection.",
    weight: 70,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
#[allow(non_camel_case_types)]
pub struct Ms10_070Plugin;

const PROBE_A: &str = "/ScriptResource.axd?d=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0";
const PROBE_B: &str = "/ScriptResource.axd?d=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1";

#[async_trait]
impl Plugin for Ms10_070Plugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut req_a = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "GET", PROBE_A)
        };
        let mut req_b = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "GET", PROBE_B)
        };
        let a = match ctx.nfetch(mark.clone(), &mut req_a).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let b = match ctx.nfetch(mark.clone(), &mut req_b).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        // A real vulnerable server returns 404 for both only when neither validates;
        // if one is 404 and the other 500 (or similar), the padding oracle is leaking.
        if a.status != b.status && (a.status == 404 || b.status == 404) {
            ctx.emit(
                mark,
                vec![ReportItem {
                    corvex_id: "MS10-070".into(),
                    method: "GET".into(),
                    uri: PROBE_A.into(),
                    message: format!(
                        "ASP.NET padding oracle (MS10-070) — ScriptResource.axd status varied ({} vs {}).",
                        a.status, b.status
                    ),
                    refs: "CVE-2010-3332,MS10-070".into(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::High,
                    cve: Some("CVE-2010-3332".into()),
                    cvss: Some(5.0),
                }],
            )
            .await;
        }
        Ok(())
    }
}
