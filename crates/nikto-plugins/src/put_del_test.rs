//! PUT / DELETE method verification.
//!
//! Strategy (mirrors `nikto_put_del_test.plugin`): probe a random filename
//! with PUT; if the server accepts it (2xx), confirm with a GET, then issue
//! a DELETE. Every step emits a finding so the operator can see exactly what
//! worked.

use async_trait::async_trait;
use nikto_core::error::Result;
use nikto_core::http::request::Request;
use nikto_core::plugin::{HookKind, Plugin, PluginInfo};
use nikto_core::report::ReportItem;
use nikto_core::scan::ScanCtx;
use nikto_core::target::Mark;
use rand::Rng;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "put_del_test",
    full_name: "PUT/DELETE Test",
    description: "Test whether PUT and DELETE methods succeed.",
    weight: 65,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct PutDelPlugin;

fn random_name() -> String {
    const CS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..10)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect()
}

#[async_trait]
impl Plugin for PutDelPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        let name = format!("/nikto-test-{}.txt", random_name());
        let body = "Nikto PUT/DELETE test marker. Safe to delete.".to_string();

        // PUT
        let mut put = {
            let m = mark.lock().await;
            let mut r = Request::new(&m.hostname, m.port, "PUT", &name);
            r.body = body.as_bytes().to_vec();
            r.set_header("Content-Type", "text/plain");
            r
        };
        let put_resp = match ctx.nfetch(mark.clone(), &mut put).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        if !(200..300).contains(&put_resp.status) {
            return Ok(());
        }

        let mut findings = vec![ReportItem {
            nikto_id: "PUT-WRITE".into(),
            method: "PUT".into(),
            uri: name.clone(),
            message: format!(
                "HTTP PUT may allow writing arbitrary files. Test file returned {}.",
                put_resp.status
            ),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
        }];

        // Confirm with GET
        let mut get = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "GET", &name)
        };
        if let Ok(get_resp) = ctx.nfetch(mark.clone(), &mut get).await {
            if get_resp.status == 200 && get_resp.body_str().contains("Nikto PUT/DELETE") {
                findings.push(ReportItem {
                    nikto_id: "PUT-CONFIRM".into(),
                    method: "GET".into(),
                    uri: name.clone(),
                    message: "PUT upload confirmed — the file is readable.".into(),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                });
            }
        }

        // Clean up with DELETE
        let mut del = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "DELETE", &name)
        };
        if let Ok(del_resp) = ctx.nfetch(mark.clone(), &mut del).await {
            if (200..300).contains(&del_resp.status) {
                findings.push(ReportItem {
                    nikto_id: "DELETE-ALLOWED".into(),
                    method: "DELETE".into(),
                    uri: name.clone(),
                    message: "HTTP DELETE succeeded on the uploaded test file.".into(),
                    refs: String::new(),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                });
            }
        }

        ctx.emit(mark.clone(), findings).await;
        Ok(())
    }
}
