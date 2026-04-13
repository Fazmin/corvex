//! OS fingerprinting plugin — combines HTTP banner, SSH banner, and
//! open port heuristics to guess the target operating system.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use corvex_core::error::Result;
use corvex_core::os_fingerprint;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::ReportItem;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

static INFO: PluginInfo = PluginInfo {
    name: "os_fingerprint",
    full_name: "OS Fingerprinting",
    description: "Guess target OS from HTTP banner, service banners, and port patterns.",
    weight: 15,
    default: true,
    extra: false,
    hooks: &[HookKind::Recon],
};

#[derive(Default)]
pub struct OsFingerprintPlugin;

#[async_trait]
impl Plugin for OsFingerprintPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_recon(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let (banner, port) = {
            let m = mark.lock().await;
            (m.banner.clone(), m.port)
        };

        // We only have the HTTP banner at this point — SSH banners and
        // open port lists come from port scanning (Phase 2A) which runs
        // before plugins. Pass them if available.
        let open_ports = vec![port];

        let guess = os_fingerprint::fingerprint(
            banner.as_deref(),
            None, // SSH banner — populated by netservices plugin later
            &open_ports,
        );

        if let Some(guess) = guess {
            if guess.confidence >= 25 {
                let version_str = guess
                    .os_version
                    .as_ref()
                    .map(|v| format!(" {v}"))
                    .unwrap_or_default();
                let evidence_str = guess.evidence.join("; ");

                ctx.emit(
                    mark,
                    vec![ReportItem {
                        corvex_id: format!(
                            "OS-{}",
                            guess.os_family.to_ascii_uppercase()
                        ),
                        method: "GET".into(),
                        uri: "/".into(),
                        message: format!(
                            "OS detected: {}{} (confidence: {}%). Evidence: {}",
                            guess.os_family, version_str, guess.confidence, evidence_str,
                        ),
                        refs: String::new(),
                        data: String::new(),
                        plugin: INFO.name.to_string(),
                        ..Default::default()
                    }],
                )
                .await;
            }
        }

        Ok(())
    }
}
