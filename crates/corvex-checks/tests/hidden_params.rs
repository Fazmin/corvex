//! Integration tests for the hidden-parameter discovery check.
//!
//! Stubs an upstream that silently honours a small set of "hidden"
//! parameters (flips to admin mode, reflects a debug canary) and
//! otherwise ignores every other parameter name. The check should
//! discover the hidden pair and stay quiet on the random parameter
//! names that don't trigger behaviour.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HReq, Response as HResp};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use corvex_checks::{default_registry, CheckCtx};
use corvex_core::http::client::HttpClient;
use corvex_core::http::request::Request as CoreReq;
use corvex_core::state::GlobalState;
use corvex_proxy::{Exchange, ExchangeOrigin, ScopeDecision, SessionId};

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

/// Upstream that accepts `/data?view=public`. It honours two hidden
/// parameters:
///   * `admin=1` → returns an admin-only block (changes response
///     shape meaningfully → shape-diff signal).
///   * `debug=<anything>` → reflects the value verbatim into the
///     response (canary reflection signal).
fn spawn_hidden_params_upstream() -> std::net::SocketAddr {
    let tcp = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = tcp.local_addr().unwrap();
    tcp.set_nonblocking(true).unwrap();
    let tcp = TcpListener::from_std(tcp).unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else { return };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: HReq<Incoming>| async move {
                    let q = req.uri().query().unwrap_or("").to_string();
                    let mut admin = false;
                    let mut debug_value: Option<String> = None;
                    for part in q.split('&') {
                        if let Some((k, v)) = part.split_once('=') {
                            if k == "admin" && v == "1" {
                                admin = true;
                            }
                            if k == "debug" {
                                debug_value = Some(
                                    urlencoding::decode(v)
                                        .map(|c| c.into_owned())
                                        .unwrap_or_else(|_| v.to_string()),
                                );
                            }
                        }
                    }
                    // Public baseline body — long enough that the
                    // trigram ratio against the admin body is well
                    // below SAME_SHAPE_THRESHOLD.
                    let mut body =
                        String::from("<html><body><h1>Public view</h1><ul><li>product A</li><li>product B</li><li>product C</li></ul></body></html>");
                    if admin {
                        body = String::from(
                            "<html><body><h1>Admin dashboard</h1><table><tr><td>user1</td><td>admin</td></tr><tr><td>user2</td><td>user</td></tr></table><p>Internal revenue $1,234,567</p><div>Recent logins: alice, bob, carol</div></body></html>",
                        );
                    }
                    if let Some(v) = &debug_value {
                        body.push_str(&format!(
                            "<!-- debug={} -->",
                            v
                        ));
                    }
                    Ok::<_, hyper::Error>(
                        HResp::builder()
                            .status(200)
                            .header("content-length", body.len().to_string())
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hidden_params_discovers_admin_and_debug() {
    let addr = spawn_hidden_params_upstream();
    let registry = default_registry();
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 16));
    let ctx = CheckCtx { client, csrf: None };

    let req = core_request(
        &addr.ip().to_string(),
        addr.port(),
        "/data?view=public",
    );
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["hidden-params".to_string()])
        .await;
    let hp: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "hidden-params")
        .collect();
    assert!(
        !hp.is_empty(),
        "expected hidden-params findings, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );

    let names: Vec<&str> = hp
        .iter()
        .filter_map(|f| f.evidence.get("param").and_then(|v| v.as_str()))
        .collect();
    assert!(
        names.contains(&"admin"),
        "expected `admin` to be discovered; found {names:?}"
    );
    assert!(
        names.contains(&"debug"),
        "expected `debug` to be discovered; found {names:?}"
    );

    // The debug hit should carry reflected=true because the upstream
    // echoes the canary into the body.
    let debug_hit = hp
        .iter()
        .find(|f| f.evidence.get("param").and_then(|v| v.as_str()) == Some("debug"))
        .unwrap();
    assert_eq!(
        debug_hit.evidence.get("reflected").and_then(|v| v.as_bool()),
        Some(true),
        "debug finding should mark canary as reflected"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hidden_params_stays_quiet_on_fully_static_endpoint() {
    // Upstream always returns the exact same body — no hidden params
    // honoured. The check must produce zero findings.
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
                    let body = "<html><body>stable page, no hidden behaviour</body></html>";
                    Ok::<_, hyper::Error>(
                        HResp::builder()
                            .status(200)
                            .header("content-length", body.len().to_string())
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let registry = default_registry();
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 16));
    let ctx = CheckCtx { client, csrf: None };

    let req = core_request(
        &addr.ip().to_string(),
        addr.port(),
        "/static?page=home",
    );
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["hidden-params".to_string()])
        .await;
    assert!(
        findings.iter().all(|f| f.check_id != "hidden-params"),
        "static endpoint must not raise hidden-params, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
