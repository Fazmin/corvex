//! Optionsbleed (CVE-2017-9798) — send OPTIONS a handful of times and look
//! for garbage / changing bytes in the Allow header. The original bug
//! leaked memory into the Allow response on specific Apache builds.

use async_trait::async_trait;
use nikto_core::error::Result;
use nikto_core::http::request::Request;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};
use nikto_core::report::ReportItem;
use nikto_core::scan::ScanCtx;
use nikto_core::target::Mark;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "optionsbleed",
    full_name: "Optionsbleed",
    description: "CVE-2017-9798 Apache memory leak in Allow header.",
    weight: 75,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct OptionsbleedPlugin;

#[async_trait]
impl Plugin for OptionsbleedPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..5 {
            let mut req = {
                let m = mark.lock().await;
                Request::new(&m.hostname, m.port, "OPTIONS", "/")
            };
            let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };
            if let Some(allow) = resp.header("allow") {
                seen.insert(allow.trim().to_string());
                // Look for non-printable bytes or suspicious characters.
                if allow
                    .bytes()
                    .any(|b| b < 0x20 || b > 0x7e)
                    || allow.contains(",,")
                {
                    ctx.emit(
                        mark.clone(),
                        vec![ReportItem {
                            nikto_id: "OPTIONSBLEED".into(),
                            method: "OPTIONS".into(),
                            uri: "/".into(),
                            message: format!(
                                "Allow header contains unexpected bytes: {allow}. Target may be vulnerable to CVE-2017-9798."
                            ),
                            refs: "CVE-2017-9798".into(),
                            data: String::new(),
                            plugin: INFO.name.to_string(),
                        }],
                    )
                    .await;
                    return Ok(());
                }
            }
        }
        if seen.len() > 1 {
            ctx.emit(
                mark,
                vec![ReportItem {
                    nikto_id: "OPTIONSBLEED-DRIFT".into(),
                    method: "OPTIONS".into(),
                    uri: "/".into(),
                    message: format!(
                        "Allow header value changed across requests ({} distinct values). Possible Optionsbleed.",
                        seen.len()
                    ),
                    refs: "CVE-2017-9798".into(),
                    data: seen.into_iter().collect::<Vec<_>>().join("\n"),
                    plugin: INFO.name.to_string(),
                }],
            )
            .await;
        }
        Ok(())
    }
}
