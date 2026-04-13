//! HTTP OPTIONS / Allow header probe.

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
    name: "options",
    full_name: "HTTP Options",
    description: "Test HTTP OPTIONS to enumerate allowed methods.",
    weight: 50,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct OptionsPlugin;

#[async_trait]
impl Plugin for OptionsPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut req = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "OPTIONS", "/")
        };
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if let Some(allow) = resp.header("allow") {
            ctx.emit(
                mark.clone(),
                vec![ReportItem {
                    corvex_id: "OPTIONS-ALLOW".into(),
                    method: "OPTIONS".into(),
                    uri: "/".into(),
                    message: format!("Allowed HTTP Methods: {allow}"),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    ..Default::default()
                }],
            )
            .await;
        }
        // Check for dangerous methods from db_options
        let methods: Vec<String> = resp
            .header("allow")
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .collect();
        let mut findings = Vec::new();
        for row in &ctx.dbs.options.rows {
            if methods.contains(&row.method.to_uppercase()) {
                findings.push(ReportItem {
                    corvex_id: row.id.clone(),
                    method: row.method.clone(),
                    uri: "/".into(),
                    message: row.message.replace("@TYPE@", "Allow"),
                    refs: row.references.clone(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::Medium,
                    ..Default::default()
                });
            }
        }
        if !findings.is_empty() {
            ctx.emit(mark.clone(), findings).await;
        }
        Ok(())
    }
}
