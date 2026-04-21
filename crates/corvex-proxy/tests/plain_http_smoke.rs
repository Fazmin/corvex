//! End-to-end smoke test for the plain-HTTP capture path.
//!
//! Spins up a tiny upstream server, starts a real [`ProxyState`]
//! listener on a loopback port, issues an absolute-form request through
//! the proxy the way a browser would, and verifies:
//!
//! 1. The proxy forwards the request and the response body round-trips.
//! 2. The live broadcast channel emits an [`Exchange`].
//! 3. The SQLite writer persists the exchange (the list query returns
//!    the row once the batched writer flushes).
//!
//! HTTPS MITM through a real browser is still a manual step — OS/browser
//! trust stores are outside anything we can drive from a test.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use corvex_proxy::{Authority, CaConfig, ProxyConfig, ProxyDb, ProxyState};

async fn upstream_hello() -> SocketAddr {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .header("x-upstream", "corvex-smoke")
                            .body(Full::new(Bytes::from_static(b"hello from upstream")))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_captures_plain_http_round_trip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("corvex_proxy=trace,corvex_core=debug")
        .with_test_writer()
        .try_init();

    // Temp directory for CA material and the proxy DB. rusqlite's bundled
    // variant doesn't care about the file path.
    let tmp = std::env::temp_dir().join(format!(
        "corvex-proxy-smoke-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let ca = Authority::load_or_generate(CaConfig::for_dir(tmp.join("ca"))).unwrap();
    let db = ProxyDb::open(tmp.join("proxy.sqlite")).unwrap();

    let state = Arc::new(ProxyState::new(Arc::new(ca), Arc::new(db)));
    let mut exchanges = state.subscribe_exchanges();

    let upstream_addr = upstream_hello().await;

    // Pick an ephemeral port for the proxy listener.
    let proxy_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    drop(proxy_listener);

    let session = state
        .start(ProxyConfig {
            listen: proxy_addr,
            note: Some("smoke".to_string()),
        })
        .await
        .expect("proxy_start");

    // Give the listener a beat to actually bind.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Speak raw HTTP/1 to the proxy with an absolute-form request line,
    // the way a browser configured with `http_proxy=proxy_addr` would.
    // Hyper's client would normalise this to origin-form, so we write
    // the wire bytes directly.
    let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
    let wire = format!(
        "GET http://{upstream_addr}/healthz HTTP/1.1\r\n\
         Host: {upstream_addr}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    client.write_all(wire.as_bytes()).await.unwrap();
    let mut buf = Vec::with_capacity(2048);
    timeout(Duration::from_secs(5), client.read_to_end(&mut buf))
        .await
        .expect("read timeout")
        .expect("read ok");
    let raw = String::from_utf8_lossy(&buf);
    assert!(raw.starts_with("HTTP/1.1 200"), "status line: {raw:?}");
    assert!(
        raw.contains("x-upstream: corvex-smoke"),
        "upstream header missing: {raw:?}"
    );
    assert!(
        raw.ends_with("hello from upstream"),
        "body mismatch: {raw:?}"
    );

    // The broadcast channel must have seen at least one exchange.
    let ex = timeout(Duration::from_secs(2), exchanges.recv())
        .await
        .expect("broadcast timeout")
        .expect("broadcast closed");
    assert_eq!(ex.request.method, "GET");
    assert!(
        ex.request.uri.starts_with("/healthz"),
        "got uri {}",
        ex.request.uri
    );
    assert_eq!(
        ex.response.as_ref().map(|r| r.status),
        Some(200),
        "captured response status mismatch"
    );

    // Give the batched writer two flush ticks to land the row.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let summaries = state
        .db()
        .list_exchanges(&session, 10, 0)
        .expect("list exchanges");
    assert!(!summaries.is_empty(), "no exchange persisted");
    let row = &summaries[0];
    assert_eq!(row.method, "GET");
    assert_eq!(row.status, Some(200));
    assert_eq!(row.host, upstream_addr.ip().to_string());

    state.stop().await.expect("stop");

    let _ = std::fs::remove_dir_all(&tmp);
}
