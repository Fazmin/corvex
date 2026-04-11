use async_trait::async_trait;
use nikto_core::error::Result;
use nikto_core::http::request::Request;
use nikto_core::http::response::Response;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};
use nikto_core::report::ReportItem;
use nikto_core::scan::ScanCtx;
use nikto_core::target::Mark;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "cookies",
    full_name: "Cookie Analysis",
    description: "Inspect Set-Cookie values for private IPs.",
    weight: 50,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

static PRIVATE_IP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b")
        .unwrap()
});

#[derive(Default)]
pub struct CookiesPlugin;

#[async_trait]
impl Plugin for CookiesPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_postfetch(
        &self,
        _ctx: &ScanCtx,
        _mark: Arc<Mutex<Mark>>,
        req: &Request,
        resp: &Response,
    ) -> Result<Vec<ReportItem>> {
        let mut items = Vec::new();
        for (k, v) in &resp.headers {
            if k.eq_ignore_ascii_case("set-cookie") && PRIVATE_IP.is_match(v) {
                items.push(ReportItem {
                    nikto_id: "COOKIE-PRIV".into(),
                    method: req.method.clone(),
                    uri: req.uri.clone(),
                    message: format!("Cookie contains an internal IP address: {v}"),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                });
            }
        }
        Ok(items)
    }
}
