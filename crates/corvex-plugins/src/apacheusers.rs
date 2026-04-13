//! Apache mod_userdir enumeration. For each known username in db_variables
//! `@USERS`, probe `/~user/` and look for a non-404 response.

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
    name: "apacheusers",
    full_name: "Apache Users",
    description: "Enumerate Apache mod_userdir accounts via /~user/.",
    weight: 60,
    default: false,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct ApacheUsersPlugin;

#[async_trait]
impl Plugin for ApacheUsersPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let users: Vec<String> = ctx
            .dbs
            .variables
            .entries
            .iter()
            .find(|(n, _)| n == "USERS")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        let mut findings = Vec::new();
        for user in users {
            let uri = format!("/~{user}/");
            let mut req = {
                let m = mark.lock().await;
                Request::new(&m.hostname, m.port, "GET", &uri)
            };
            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if resp.status != 404 && resp.status != 410 {
                findings.push(ReportItem {
                    corvex_id: format!("USERDIR-{user}"),
                    method: "GET".into(),
                    uri,
                    message: format!(
                        "Apache mod_userdir exposed account `{user}` (HTTP {}).",
                        resp.status
                    ),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: Severity::Low,
                    ..Default::default()
                });
            }
        }
        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }
        Ok(())
    }
}
