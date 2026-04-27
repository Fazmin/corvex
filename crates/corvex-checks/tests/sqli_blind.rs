//! Integration tests for the boolean-blind + time-based blind SQLi
//! active checks.
//!
//! Stubs a local hyper upstream that simulates two classes of bug:
//!   * A numeric parameter whose value steers an `... WHERE id = ?`
//!     query. Requests with `id=5 AND 1=1` render the original record;
//!     requests with `id=5 AND 1=2` render an empty row.
//!   * A parameter that honors a SLEEP() call by blocking the response.
//!
//! The checks are wired through the real CheckRegistry so we exercise
//! the same code path the proxy does.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HReq, Response as HResp};
use hyper_util::rt::TokioIo;
use indexmap::IndexMap;
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

fn parse_query<'a>(q: &'a str) -> IndexMap<String, String> {
    let mut m = IndexMap::new();
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            let decoded_v = urlencoding::decode(v)
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| v.to_string());
            m.insert(k.to_string(), decoded_v);
        }
    }
    m
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boolean_blind_sqli_detects_true_vs_false_diff() {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else { return };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: HReq<Incoming>| async move {
                    let q = req.uri().query().unwrap_or("").to_string();
                    let params = parse_query(&q);
                    let id = params.get("id").cloned().unwrap_or_default();

                    // Simulate a vulnerable query `SELECT * FROM users
                    // WHERE id = $id`. No error messages are leaked —
                    // the app only varies content.
                    let true_body =
                        "<html><body><h1>Order 5</h1><p>Status: shipped</p><p>Total: $42.00</p></body></html>";
                    let false_body = "<html><body><h1>No results</h1></body></html>";

                    // Treat anything that includes `1=1` (our TRUE
                    // probe) as still-matching the record, and `1=2`
                    // as missing. Numeric-only values return the true
                    // body too.
                    let body = if id.contains("1=2") {
                        false_body
                    } else {
                        true_body
                    };
                    Ok::<_, hyper::Error>(
                        HResp::builder()
                            .status(200)
                            .header("content-type", "text/html")
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
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client, csrf: None };

    let req = core_request(&upstream.ip().to_string(), upstream.port(), "/order?id=5");
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["boolean-blind-sqli".to_string()])
        .await;
    assert!(
        !findings.is_empty(),
        "boolean-blind-sqli should flag the `id` parameter"
    );
    let hit = findings
        .iter()
        .find(|f| f.check_id == "boolean-blind-sqli")
        .expect("boolean-blind-sqli finding missing");
    assert!(
        hit.title.contains("`id`"),
        "finding should mention the vulnerable param, got: {}",
        hit.title
    );
    let evidence = &hit.evidence;
    assert_eq!(evidence["param"].as_str(), Some("id"));
    assert!(evidence["boundary"].is_string());
    // Similarity ratios should make sense.
    let rt = evidence["ratio_true_vs_baseline"].as_f64().unwrap();
    let rf = evidence["ratio_false_vs_baseline"].as_f64().unwrap();
    assert!(rt > rf, "true should be more similar to baseline than false");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boolean_blind_sqli_quiet_when_response_is_static() {
    // Upstream always returns the same body regardless of input —
    // boolean-blind should stay quiet rather than raise a false
    // positive.
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else { return };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: HReq<Incoming>| async move {
                    let body = "<html><body>static content</body></html>";
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
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client, csrf: None };

    let req = core_request(&upstream.ip().to_string(), upstream.port(), "/ok?id=5");
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["boolean-blind-sqli".to_string()])
        .await;
    assert!(
        findings.iter().all(|f| f.check_id != "boolean-blind-sqli"),
        "static page should not raise boolean-blind-sqli, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn time_based_sqli_detects_sleep_on_injectable_param() {
    // Upstream implements a toy time-based oracle: if the query
    // contains `SLEEP(N)`, the handler delays for N seconds before
    // responding.
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else { return };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: HReq<Incoming>| async move {
                    let q = req.uri().query().unwrap_or("").to_string();
                    let decoded = urlencoding::decode(&q)
                        .map(|s| s.into_owned())
                        .unwrap_or(q.clone());

                    // Look for a SLEEP(<digits>) pattern anywhere in
                    // the query. This simulates a backend that trusts
                    // concatenated input and passes it to a DBMS that
                    // honours sleep calls.
                    let secs: Option<u64> = {
                        let lower = decoded.to_ascii_lowercase();
                        let mut out = None;
                        for pat in ["sleep(", "pg_sleep(", "waitfor delay '0:0:"] {
                            if let Some(idx) = lower.find(pat) {
                                let rest = &lower[idx + pat.len()..];
                                let digits: String = rest
                                    .chars()
                                    .take_while(|c| c.is_ascii_digit())
                                    .collect();
                                if let Ok(n) = digits.parse::<u64>() {
                                    out = Some(n);
                                    break;
                                }
                            }
                        }
                        out
                    };

                    if let Some(s) = secs {
                        tokio::time::sleep(Duration::from_secs(s)).await;
                    }
                    let body = "ok";
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
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client, csrf: None };

    let req = core_request(
        &upstream.ip().to_string(),
        upstream.port(),
        "/user?uid=1",
    );
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["time-based-sqli".to_string()])
        .await;
    let hit = findings
        .iter()
        .find(|f| f.check_id == "time-based-sqli")
        .expect("time-based-sqli finding missing");
    assert!(hit.title.contains("`uid`"));
    let evidence = &hit.evidence;
    assert_eq!(evidence["param"].as_str(), Some("uid"));
    // Confirmation probe should show ~7s of added delay.
    let confirm_ms = evidence["confirm_elapsed_ms"].as_u64().unwrap_or(0);
    assert!(
        confirm_ms >= 6_000,
        "confirm_elapsed_ms should reflect the 7s sleep, got {confirm_ms}ms"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn time_based_sqli_stays_quiet_on_fast_endpoint() {
    // Upstream responds instantly regardless of query — no SLEEP
    // handling. Time-based must not raise a finding.
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else { return };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: HReq<Incoming>| async move {
                    let body = "fast";
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
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client, csrf: None };

    let req = core_request(&upstream.ip().to_string(), upstream.port(), "/ok?q=1");
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["time-based-sqli".to_string()])
        .await;
    assert!(
        findings.iter().all(|f| f.check_id != "time-based-sqli"),
        "fast endpoint should not raise time-based-sqli: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
