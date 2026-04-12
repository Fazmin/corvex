//! Spring Boot actuator enumeration.
//!
//! Known sensitive actuator paths (Spring Boot 1.x + 2.x+ layouts) probed
//! under both `/` and `/actuator/`. Any 200 response is reported.

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
    name: "springboot",
    full_name: "Spring Boot Actuator",
    description: "Probe Spring Boot actuator endpoints for information disclosure.",
    weight: 70,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct SpringbootPlugin;

const PREFIXES: &[&str] = &["", "/actuator"];
const ENDPOINTS: &[(&str, &str)] = &[
    ("/env", "Environment dump (potentially contains credentials)"),
    ("/trace", "Request trace log"),
    ("/dump", "Thread dump"),
    ("/heapdump", "JVM heap dump"),
    ("/loggers", "Logger configuration"),
    ("/configprops", "Configuration properties"),
    ("/beans", "Spring bean graph"),
    ("/mappings", "Request mappings"),
    ("/health", "Health endpoint"),
    ("/info", "Build / git info"),
    ("/metrics", "Application metrics"),
    ("/auditevents", "Audit events"),
    ("/shutdown", "Shutdown endpoint — POST may halt the application"),
    ("/jolokia/list", "Jolokia MBean list (may allow RCE)"),
];

#[async_trait]
impl Plugin for SpringbootPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut findings = Vec::new();
        for prefix in PREFIXES {
            for (path, descr) in ENDPOINTS {
                let uri = format!("{prefix}{path}");
                let mut req = {
                    let m = mark.lock().await;
                    Request::new(&m.hostname, m.port, "GET", &uri)
                };
                let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if resp.status == 200 {
                    findings.push(ReportItem {
                        corvex_id: format!("SPRINGBOOT{}", path.replace('/', "-")),
                        method: "GET".into(),
                        uri,
                        message: format!("Spring Boot actuator exposed: {descr}"),
                        refs: String::new(),
                        data: String::new(),
                        plugin: INFO.name.to_string(),
                    });
                }
            }
        }
        if !findings.is_empty() {
            ctx.emit(mark, findings).await;
        }
        Ok(())
    }
}
