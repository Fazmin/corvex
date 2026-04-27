//! End-to-end smoke tests for Phase 3 checks — passive inspection of a
//! synthetic exchange, plus an active check driven through a local
//! upstream.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use indexmap::IndexMap;
use tokio::net::TcpListener;

use corvex_checks::{default_registry, CheckCtx, Finding};
use corvex_core::http::{client::HttpClient, request::Request as CoreReq, response::Response as CoreResp};
use corvex_core::state::GlobalState;
use corvex_proxy::{Exchange, ExchangeOrigin, ScopeDecision, SessionId};

fn headers_from(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
    let mut m = IndexMap::new();
    for (k, v) in pairs {
        m.insert((*k).to_string(), (*v).to_string());
    }
    m
}

fn synth_exchange(
    ssl: bool,
    response_headers: &[(&str, &str)],
    response_body: &[u8],
) -> Exchange {
    let mut req = CoreReq::new("example.com", if ssl { 443 } else { 80 }, "GET", "/page");
    req.ssl = ssl;
    let resp = CoreResp {
        status: 200,
        status_text: "OK".into(),
        version: "1.1".into(),
        headers: headers_from(response_headers),
        body: response_body.to_vec(),
        error: None,
        tls: None,
        elapsed: std::time::Duration::ZERO,
    };
    let mut ex = Exchange::new(
        SessionId::new(),
        ExchangeOrigin::Imported {
            source: "test".into(),
        },
        req,
        ScopeDecision::InScope,
    );
    ex.response = Some(resp);
    ex
}

#[test]
fn passive_security_headers_flag_missing_csp_on_https() {
    let registry = default_registry();
    let exchange = synth_exchange(true, &[("Content-Type", "text/html")], b"<html>");
    let findings: Vec<Finding> = registry.run_passive(&exchange);
    let titles: Vec<_> = findings.iter().map(|f| f.title.clone()).collect();
    assert!(
        titles
            .iter()
            .any(|t| t.contains("Content-Security-Policy")),
        "expected CSP finding, got: {titles:?}"
    );
    assert!(
        titles
            .iter()
            .any(|t| t.contains("Strict-Transport-Security")),
        "expected HSTS finding on HTTPS, got: {titles:?}"
    );
}

#[test]
fn passive_insecure_cookies_flags_missing_flags() {
    // Response headers use a single-valued map today, so the test
    // focuses on a single cookie missing every attribute.
    let registry = default_registry();
    let exchange = synth_exchange(
        true,
        &[
            ("Content-Type", "text/html"),
            ("Set-Cookie", "session=abc; Path=/"),
        ],
        b"<html>",
    );
    let findings = registry.run_passive(&exchange);
    let cookie_titles: Vec<_> = findings
        .iter()
        .filter(|f| f.check_id == "insecure-cookies")
        .map(|f| f.title.clone())
        .collect();
    assert!(
        cookie_titles
            .iter()
            .any(|t| t.contains("session")
                && t.contains("Secure")
                && t.contains("HttpOnly")
                && t.contains("SameSite")),
        "session cookie missing-flags finding not raised: {cookie_titles:?}"
    );
}

#[test]
fn passive_insecure_cookies_accepts_well_formed_cookie() {
    let registry = default_registry();
    let exchange = synth_exchange(
        true,
        &[
            ("Content-Type", "text/html"),
            ("Set-Cookie", "pref=dark; Secure; HttpOnly; SameSite=Lax"),
        ],
        b"<html>",
    );
    let findings = registry.run_passive(&exchange);
    assert!(
        findings
            .iter()
            .all(|f| f.check_id != "insecure-cookies"),
        "well-formed cookie raised false positive: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn passive_verbose_errors_catches_python_traceback() {
    let registry = default_registry();
    let body = b"<html><pre>Traceback (most recent call last):\n  File \"/app.py\", line 42, in foo\n    bar()\n</pre></html>";
    let exchange = synth_exchange(false, &[("Content-Type", "text/html")], body);
    let findings = registry.run_passive(&exchange);
    assert!(
        findings.iter().any(|f| f.title.contains("Stack trace")),
        "stack trace not detected: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[test]
fn passive_stack_fingerprint_identifies_nginx_php() {
    let registry = default_registry();
    let exchange = synth_exchange(
        true,
        &[
            ("Server", "nginx/1.24.0"),
            ("X-Powered-By", "PHP/8.2.4"),
            ("Content-Type", "text/html"),
        ],
        b"<html></html>",
    );
    let findings = registry.run_passive(&exchange);
    let stack = findings
        .iter()
        .find(|f| f.check_id == "stack-fingerprint")
        .expect("stack fingerprint finding");
    let detections = stack
        .evidence
        .get("detections")
        .and_then(|v| v.as_array())
        .unwrap();
    let names: Vec<_> = detections
        .iter()
        .filter_map(|d| d.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(names.contains(&"nginx"), "nginx not detected: {names:?}");
    assert!(names.contains(&"PHP"), "PHP not detected: {names:?}");
}

#[test]
fn passive_version_disclosure_extracts_banner() {
    let registry = default_registry();
    let exchange = synth_exchange(
        true,
        &[
            ("Server", "nginx/1.24.0"),
            ("X-Powered-By", "PHP/8.2.4"),
            ("Content-Type", "text/html"),
        ],
        b"<html></html>",
    );
    let findings = registry.run_passive(&exchange);
    assert!(
        findings
            .iter()
            .any(|f| f.check_id == "version-disclosure"),
        "version banner not detected"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_open_redirect_detects_sentinel_bounce() {
    // Upstream echoes `?redirect=` into a Location header.
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let q = req.uri().query().unwrap_or("");
                    let redirect = q
                        .split('&')
                        .find_map(|kv| kv.strip_prefix("redirect="))
                        .unwrap_or("/")
                        .to_string();
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(302)
                            .header(
                                "Location",
                                urlencoding::decode(&redirect).unwrap().into_owned(),
                            )
                            .header("content-length", "0")
                            .body(Full::new(Bytes::new()))
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

    // Base exchange has a URL-shaped `redirect` parameter so the check
    // targets it.
    let mut req = CoreReq::new(
        &upstream.ip().to_string(),
        upstream.port(),
        "GET",
        "/r?redirect=/safe",
    );
    req.ssl = false;
    req.headers.insert("Connection".into(), "close".into());
    let exchange = Exchange::new(
        SessionId::new(),
        ExchangeOrigin::Imported {
            source: "test".into(),
        },
        req,
        ScopeDecision::InScope,
    );

    let ctx = CheckCtx {
        client: client.clone(),
        csrf: None,
    };
    let findings = registry
        .run_active(&ctx, &exchange, &vec!["open-redirect".to_string()])
        .await;
    assert!(
        !findings.is_empty(),
        "open redirect not detected against sentinel echo"
    );
    let evidence_locations: Vec<_> = findings
        .iter()
        .filter_map(|f| f.evidence.get("location").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    assert!(
        evidence_locations
            .iter()
            .any(|l| l.contains("corvex-redirect-canary.invalid")),
        "expected sentinel in Location: {evidence_locations:?}"
    );
}
