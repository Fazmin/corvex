//! Integration test for the `nuclei-active` check.
//!
//! Writes a minimal high-severity Nuclei template to a temp dir,
//! loads it into a fresh `TemplateStore`, builds a CheckRegistry with
//! `with_templates`, and runs it against a hyper upstream that
//! purposefully emits the matcher string only on the template's
//! target path. Proves that the active check actually sends HTTP
//! requests (vs. the passive matcher-only path).

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HReq, Response as HResp};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use uuid::Uuid;

use corvex_checks::{passive::TemplateChecks, CheckCtx, CheckRegistry};
use corvex_core::http::client::HttpClient;
use corvex_core::http::request::Request as CoreReq;
use corvex_core::state::GlobalState;
use corvex_nuclei::store::TemplateStore;
use corvex_proxy::{Exchange, ExchangeOrigin, ScopeDecision, SessionId};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("corvex-nuclei-active-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn core_request(host: &str, port: u16, uri: &str) -> CoreReq {
    let mut r = CoreReq::new(host, port, "GET", uri);
    r.ssl = false;
    r.headers.insert("Connection".into(), "close".into());
    r
}

fn synth_exchange(req: CoreReq) -> Exchange {
    Exchange::new(
        SessionId::new(),
        ExchangeOrigin::Imported { source: "test".into() },
        req,
        ScopeDecision::InScope,
    )
}

/// A minimal Nuclei-HTTP template. Severity is critical so it passes
/// the default filter; tags include `rce` to double-confirm. The
/// matcher looks for the string `CORVEX_HIT_MARKER_XYZ` anywhere in
/// the response body.
const TEST_TEMPLATE_YAML: &str = r#"id: test-corvex-active-demo

info:
  name: Corvex active nuclei test demo
  author: corvex-checks-tests
  severity: critical
  tags:
    - rce
    - test
  description: |
    Synthetic template used by corvex-checks integration tests to
    verify the nuclei-active execution path.

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/debug"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "CORVEX_HIT_MARKER_XYZ"
      - type: status
        status:
          - 200
"#;

fn build_store_with_demo_template(dir: &TempDir) -> Arc<TemplateStore> {
    let tpl_path = dir.0.join("demo.yaml");
    std::fs::write(&tpl_path, TEST_TEMPLATE_YAML).expect("write template");

    let mut store = TemplateStore::new();
    store
        .load_dir(&dir.0)
        .expect("load temp dir of templates");
    assert!(
        store.get("test-corvex-active-demo").is_some(),
        "demo template should have loaded (store has {} entries)",
        store.len()
    );
    Arc::new(store)
}

fn registry_with_store(store: Arc<TemplateStore>) -> CheckRegistry {
    let templates = Arc::new(TemplateChecks::new(store));
    // Start from the default registry (no vulndb, no upstream
    // fingerprints) so the test stays hermetic.
    corvex_checks::default_registry().with_templates(templates)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nuclei_active_fires_template_against_target_base_url() {
    // Upstream: /admin/debug returns the marker; everything else
    // returns something harmless.
    let tcp = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = tcp.local_addr().unwrap();
    tcp.set_nonblocking(true).unwrap();
    let tcp = TcpListener::from_std(tcp).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else { return };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: HReq<Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let body: &[u8] = if path == "/admin/debug" {
                        b"<html>CORVEX_HIT_MARKER_XYZ - debug page ok</html>"
                    } else {
                        b"<html>nothing to see here</html>"
                    };
                    Ok::<_, hyper::Error>(
                        HResp::builder()
                            .status(200)
                            .header("content-length", body.len().to_string())
                            .body(Full::new(Bytes::from(body.to_vec())))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let dir = TempDir::new();
    let store = build_store_with_demo_template(&dir);
    let registry = registry_with_store(store);
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client, csrf: None };

    // Target exchange is for `/` — crucially, the template's real
    // path is `/admin/debug`, which has never been seen in traffic.
    // This is exactly the case the passive matcher-only path can't
    // handle and the active executor can.
    let req = core_request(&addr.ip().to_string(), addr.port(), "/");
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["nuclei-active".to_string()])
        .await;
    let hit = findings
        .iter()
        .find(|f| f.check_id == "nuclei-active:test-corvex-active-demo")
        .expect("nuclei-active should fire the demo template");
    assert!(hit.title.contains("Corvex active nuclei test demo"));
    let last_uri = hit
        .evidence
        .get("last_request_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        last_uri.ends_with("/admin/debug"),
        "evidence should record the target path the executor hit, got {last_uri}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nuclei_active_stays_quiet_when_template_marker_absent() {
    // Same template, but the upstream no longer emits the marker —
    // the template's matcher won't fire. Zero findings expected.
    let tcp = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = tcp.local_addr().unwrap();
    tcp.set_nonblocking(true).unwrap();
    let tcp = TcpListener::from_std(tcp).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else { return };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: HReq<Incoming>| async move {
                    let body = b"<html>unaffected</html>";
                    Ok::<_, hyper::Error>(
                        HResp::builder()
                            .status(200)
                            .header("content-length", body.len().to_string())
                            .body(Full::new(Bytes::from(body.to_vec())))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let dir = TempDir::new();
    let store = build_store_with_demo_template(&dir);
    let registry = registry_with_store(store);
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client, csrf: None };

    let req = core_request(&addr.ip().to_string(), addr.port(), "/");
    let exchange = synth_exchange(req);
    let findings = registry
        .run_active(&ctx, &exchange, &vec!["nuclei-active".to_string()])
        .await;
    assert!(
        findings
            .iter()
            .all(|f| !f.check_id.starts_with("nuclei-active")),
        "nuclei-active should not fire without the matcher string in the body; got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
