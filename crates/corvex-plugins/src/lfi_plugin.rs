//! Active Local File Inclusion detector.
//!
//! Injects classic path-traversal sequences into every parameter and
//! looks for distinctive byte patterns from well-known system files
//! (`/etc/passwd` on Unix, `boot.ini` / `win.ini` on Windows). A
//! legitimate response that happens to contain `root:x:` is vanishingly
//! rare — so the signature-match is a reliable positive.
//!
//! This is the *active* complement to the signature-based LFI checks
//! that run in the Scan hook. Those look for hardcoded CVE paths; this
//! one tries every exposed parameter to see whether the application
//! itself is reading from user input.

use std::sync::Mutex as StdMutex;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use corvex_core::crawler::CrawlGraph;
use corvex_core::error::Result;
use corvex_core::fuzzer::param::{FuzzTarget, InjectionPoint};
use corvex_core::fuzzer::runner::{FuzzResult, FuzzRunner};
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

use crate::active_util::{body_snippet, format_point, truncate};

static INFO: PluginInfo = PluginInfo {
    name: "lfi_active",
    full_name: "Local File Inclusion (active)",
    description: "Path-traversal payloads against every injection point, with body-side fingerprint matching for /etc/passwd, /etc/hosts, and Windows boot.ini / win.ini. Confirms LFI when the response contains a distinctive system-file marker.",
    weight: 58,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

fn payloads() -> Vec<(String, &'static str)> {
    // (payload, expected-marker). The marker is a byte pattern that's
    // nearly unique to the targeted file — root:x: only appears in
    // /etc/passwd-style files; [boot loader] heads every boot.ini.
    let traversals = [
        "../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
    ];
    let win_traversals = [
        "..\\..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\boot.ini",
        "c:\\windows\\win.ini",
        "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ];
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for p in traversals {
        // root:x: is present in every non-trivial /etc/passwd.
        out.push((p.to_string(), "root:x:"));
    }
    for p in win_traversals {
        // [extensions] / [fonts] / [mail] — early section headers in
        // win.ini. boot.ini is reliably prefixed with "[boot loader]".
        out.push((p.to_string(), "[extensions]"));
        out.push((p.to_string(), "[boot loader]"));
        out.push((p.to_string(), "# Copyright (c)"));
    }
    out
}

#[derive(Default)]
pub struct LfiPlugin;

fn finding(
    method: &str,
    uri: &str,
    point: &InjectionPoint,
    payload: &str,
    marker: &str,
) -> ReportItem {
    let point_label = format_point(point);
    ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message: format!(
            "Local File Inclusion: path-traversal payload {payload_short:?} in the \
             {point_label} parameter caused the response to include the \
             distinctive marker {marker:?}, indicating the application read \
             from an attacker-controlled path.",
            payload_short = truncate(payload, 160)
        ),
        refs: "CWE-22 | CWE-98".into(),
        data: String::new(),
        plugin: "lfi_active".to_string(),
        severity: Severity::Critical,
        ..Default::default()
    }
}

#[async_trait]
impl Plugin for LfiPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        let raw = payloads();
        // De-dupe the payload list for the fuzzer — the runner doesn't
        // care about markers, we do the marker check ourselves in the
        // detector.
        let mut seen = std::collections::HashSet::new();
        let payloads: Vec<String> = raw
            .iter()
            .filter_map(|(p, _)| {
                if seen.insert(p.clone()) {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .collect();

        // Pre-group markers by payload so the detector knows which set
        // of byte patterns to check against which payload's response.
        let marker_for: std::collections::HashMap<String, Vec<&'static str>> = {
            let mut m: std::collections::HashMap<String, Vec<&'static str>> =
                std::collections::HashMap::new();
            for (p, mk) in &raw {
                m.entry(p.clone()).or_default().push(*mk);
            }
            m
        };

        for page in &graph.pages {
            if ctx.is_cancelled() {
                break;
            }
            let targets = FuzzTarget::from_crawled(page);
            for target in &targets {
                if ctx.is_cancelled() {
                    break;
                }
                if target.points.is_empty() {
                    continue;
                }
                let hits: StdMutex<Vec<ReportItem>> = StdMutex::new(Vec::new());
                let method = target.method.clone();

                FuzzRunner::run(
                    ctx,
                    mark.clone(),
                    target,
                    &payloads,
                    None,
                    |r: FuzzResult| -> bool {
                        let markers = match marker_for.get(&r.payload) {
                            Some(v) => v,
                            None => return false,
                        };
                        let snippet = body_snippet(&r.response.body, 64 * 1024);
                        for m in markers {
                            if snippet.contains(m) {
                                hits.lock().unwrap().push(finding(
                                    &method,
                                    &r.target_url,
                                    &r.point,
                                    &r.payload,
                                    m,
                                ));
                                return true;
                            }
                        }
                        false
                    },
                )
                .await?;

                let hits = hits.into_inner().unwrap();
                if !hits.is_empty() {
                    ctx.emit(mark.clone(), hits).await;
                }
            }
        }
        Ok(())
    }
}
