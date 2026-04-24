//! Integration tests for the SSRF active check.
//!
//! Stubs a hyper upstream that simulates a "url fetcher" endpoint:
//! `GET /proxy?u=<target>` issues a GET against `<target>` server-side
//! and returns whatever it received. The stub fakes both AWS IMDS and
//! a local "Welcome to nginx" page so the check's marker matching is
//! exercised end-to-end.

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

/// Simulated SSRF-prone upstream. Accepts `?u=<url>` and echoes
/// pre-canned bodies that mimic AWS IMDS and an nginx default page —
/// this is the "vulnerable application fetching attacker URLs" shape
/// the check is designed to catch.
fn spawn_ssrf_upstream(
    reflect_on_metadata: bool,
    reflect_on_loopback: bool,
) -> std::net::SocketAddr {
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
                    let mut target = String::new();
                    for part in q.split('&') {
                        if let Some(v) = part.strip_prefix("u=") {
                            target = urlencoding::decode(v)
                                .map(|c| c.into_owned())
                                .unwrap_or_else(|_| v.to_string());
                            break;
                        }
                    }

                    // Fake server-side fetch. Real SSRF test fixtures
                    // would use a full HTTP client; for the check's
                    // oracle it's enough to hand back the body the
                    // real internal endpoint would have.
                    let body: &[u8] = if target.starts_with("http://169.254.169.254/latest/meta-data/iam")
                    {
                        if reflect_on_metadata {
                            b"{\"Code\":\"Success\",\"AccessKeyId\":\"ASIAXXXEXAMPLE\",\"SecretAccessKey\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",\"Token\":\"abc\",\"Expiration\":\"2030-01-01T00:00:00Z\"}"
                        } else {
                            b"blocked"
                        }
                    } else if target.starts_with("http://169.254.169.254/latest/meta-data") {
                        if reflect_on_metadata {
                            b"ami-id\nami-launch-index\ninstance-id\nsecurity-credentials/\niam/info\npublic-keys/"
                        } else {
                            b"blocked"
                        }
                    } else if target.starts_with("http://127.0.0.1")
                        || target.starts_with("http://localhost")
                        || target.starts_with("http://2130706433")
                    {
                        if reflect_on_loopback {
                            b"<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>"
                        } else {
                            b"blocked"
                        }
                    } else {
                        b"<html><body>ok, baseline page with no sensitive markers</body></html>"
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
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssrf_detects_aws_imds_credentials_leak() {
    let addr = spawn_ssrf_upstream(true, false);
    let registry = default_registry();
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client };

    // The `u` parameter carries a URL-shaped value so the SSRF
    // heuristic considers it worth probing.
    let req = core_request(
        &addr.ip().to_string(),
        addr.port(),
        "/proxy?u=https%3A%2F%2Fexample.com%2F",
    );
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["ssrf".to_string()])
        .await;
    assert!(!findings.is_empty(), "expected SSRF findings, got none");
    let critical_aws = findings.iter().find(|f| {
        f.check_id == "ssrf"
            && f.evidence
                .get("probe")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("aws-imds"))
                .unwrap_or(false)
    });
    assert!(
        critical_aws.is_some(),
        "expected aws-imds SSRF finding, titles seen: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    let f = critical_aws.unwrap();
    // Credential leak variant should hit Critical severity.
    use corvex_checks::Severity;
    assert!(
        matches!(f.severity, Severity::Critical | Severity::High),
        "expected high/critical severity for IMDS leak, got {:?}",
        f.severity
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssrf_detects_loopback_via_default_nginx_page() {
    let addr = spawn_ssrf_upstream(false, true);
    let registry = default_registry();
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client };

    let req = core_request(
        &addr.ip().to_string(),
        addr.port(),
        "/proxy?u=https%3A%2F%2Fexample.com%2F",
    );
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["ssrf".to_string()])
        .await;
    let loopback = findings.iter().find(|f| {
        f.evidence
            .get("probe")
            .and_then(|v| v.as_str())
            .map(|s| s.starts_with("loopback") || s == "localhost")
            .unwrap_or(false)
    });
    assert!(
        loopback.is_some(),
        "expected loopback SSRF finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssrf_quiet_when_upstream_blocks_all_probes() {
    // Upstream returns the same static page regardless of input —
    // simulates a well-behaved URL validator that refuses all our
    // probes. The SSRF check must not raise anything.
    let addr = spawn_ssrf_upstream(false, false);
    let registry = default_registry();
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client };

    let req = core_request(
        &addr.ip().to_string(),
        addr.port(),
        "/proxy?u=https%3A%2F%2Fexample.com%2F",
    );
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["ssrf".to_string()])
        .await;
    assert!(
        findings.iter().all(|f| f.check_id != "ssrf"),
        "expected no SSRF findings on blocked upstream, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssrf_skips_params_without_url_shaped_values() {
    // Same vulnerable upstream as the positive test — but this time
    // the target URL's only parameter is a numeric id, which the URL
    // heuristic rejects. No requests should be issued (beyond the
    // baseline), no findings should be emitted.
    let addr = spawn_ssrf_upstream(true, true);
    let registry = default_registry();
    let client = Arc::new(HttpClient::new(Arc::new(GlobalState::new()), 10));
    let ctx = CheckCtx { client };

    let req = core_request(&addr.ip().to_string(), addr.port(), "/item?id=42");
    let exchange = synth_exchange(req);

    let findings = registry
        .run_active(&ctx, &exchange, &vec!["ssrf".to_string()])
        .await;
    assert!(
        findings.iter().all(|f| f.check_id != "ssrf"),
        "numeric id param should not be probed, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
