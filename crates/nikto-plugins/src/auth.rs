//! Extract HTTP authentication realms from WWW-Authenticate and match
//! them against db_realms to identify known devices / default credentials.

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
    name: "auth",
    full_name: "HTTP Authentication",
    description: "Detect HTTP auth realms and match against db_realms.",
    weight: 40,
    default: true,
    extra: false,
    hooks: &[HookKind::Postfetch],
};

static REALM_RX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)realm\s*=\s*"([^"]*)""#).unwrap());

#[derive(Default)]
pub struct AuthPlugin;

#[async_trait]
impl Plugin for AuthPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_postfetch(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        req: &Request,
        resp: &Response,
    ) -> Result<Vec<ReportItem>> {
        let auth = match resp.header("www-authenticate") {
            Some(a) => a.to_string(),
            None => return Ok(Vec::new()),
        };

        // Avoid re-emitting on every request for the same realm.
        let already_seen = {
            let m = mark.lock().await;
            m.realms.contains_key(&auth)
        };
        if already_seen {
            return Ok(Vec::new());
        }
        {
            let mut m = mark.lock().await;
            m.realms.insert(
                auth.clone(),
                nikto_core::target::Realm {
                    auth_type: auth.split_whitespace().next().unwrap_or("").to_string(),
                    realm: auth.clone(),
                    user: None,
                    pass: None,
                },
            );
        }

        let realm_name = REALM_RX
            .captures(&auth)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        let mut items = vec![ReportItem {
            nikto_id: "AUTH-REALM".into(),
            method: req.method.clone(),
            uri: req.uri.clone(),
            message: format!("HTTP authentication required: {auth}"),
            refs: String::new(),
            data: String::new(),
            plugin: INFO.name.to_string(),
        }];

        // Match against db_realms (exact or @ANY)
        if !realm_name.is_empty() {
            for row in &ctx.dbs.realms.rows {
                if row.realm == realm_name || row.realm == "@ANY" {
                    items.push(ReportItem {
                        nikto_id: row.id.clone(),
                        method: req.method.clone(),
                        uri: req.uri.clone(),
                        message: format!(
                            "Realm `{}` matches: {}{}",
                            realm_name,
                            row.message,
                            if !row.user.is_empty() || !row.password.is_empty() {
                                format!(" (default creds: {}:{})", row.user, row.password)
                            } else {
                                String::new()
                            }
                        ),
                        refs: String::new(),
                        data: String::new(),
                        plugin: INFO.name.to_string(),
                    });
                    break;
                }
            }
        }
        Ok(items)
    }
}
