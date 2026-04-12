//! Probe for common leftover / backup / config files that shouldn't be
//! web-accessible. These are not covered by db_tests since they're
//! technology-agnostic.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "sitefiles",
    full_name: "Site Files",
    description: "Probe for leftover / backup / config files under the web root.",
    weight: 60,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct SitefilesPlugin;

const CANDIDATES: &[(&str, &str)] = &[
    ("/.git/HEAD", "Exposed .git repository (.git/HEAD reachable)"),
    ("/.git/config", "Exposed .git repository (.git/config reachable)"),
    ("/.svn/entries", "Exposed .svn repository"),
    ("/.hg/store", "Exposed Mercurial repository"),
    ("/.env", "Exposed .env file (may contain secrets)"),
    ("/.DS_Store", "macOS .DS_Store metadata exposed"),
    ("/composer.json", "composer.json exposed"),
    ("/composer.lock", "composer.lock exposed"),
    ("/package.json", "package.json exposed"),
    ("/package-lock.json", "package-lock.json exposed"),
    ("/yarn.lock", "yarn.lock exposed"),
    ("/web.config", "IIS web.config exposed"),
    ("/.htaccess", "Apache .htaccess exposed"),
    ("/WEB-INF/web.xml", "Tomcat/WEB-INF/web.xml exposed"),
    ("/backup.zip", "Generic backup file (backup.zip) present"),
    ("/backup.tar.gz", "Generic backup file (backup.tar.gz) present"),
    ("/dump.sql", "SQL dump (dump.sql) exposed"),
];

#[async_trait]
impl Plugin for SitefilesPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut findings = Vec::new();
        for (path, msg) in CANDIDATES {
            let mut req = {
                let m = mark.lock().await;
                Request::new(&m.hostname, m.port, "GET", path)
            };
            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if resp.status == 200 && !resp.body.is_empty() {
                findings.push(ReportItem {
                    corvex_id: format!("SITEFILE-{}", path.replace('/', "_")),
                    method: "GET".into(),
                    uri: (*path).into(),
                    message: (*msg).into(),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                });
            }
        }
        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }
        Ok(())
    }
}
