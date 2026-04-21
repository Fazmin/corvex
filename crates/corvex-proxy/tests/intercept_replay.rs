//! End-to-end smoke test for Phase 2: intercept with edit + replay.

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

use corvex_proxy::{
    Authority, CaConfig, InterceptMode, InterceptVerdict, ProxyConfig, ProxyDb, ProxyState,
};

async fn echo_upstream() -> std::net::SocketAddr {
    let tcp = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = tcp.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    // Echo the request path back in a header so we can
                    // tell the original apart from an edited one.
                    let path = req.uri().path().to_string();
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("x-echo-path", path)
                            .body(Full::new(Bytes::from_static(b"ok")))
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

fn tmpdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "corvex-intercept-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intercept_edits_path_before_forward() {
    let tmp = tmpdir();
    let ca = Authority::load_or_generate(CaConfig::for_dir(tmp.join("ca"))).unwrap();
    let db = ProxyDb::open(tmp.join("proxy.sqlite")).unwrap();
    let state = Arc::new(ProxyState::new(Arc::new(ca), Arc::new(db)));

    let upstream_addr = echo_upstream().await;

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);

    let _session = state
        .start(ProxyConfig {
            listen: proxy_addr,
            note: None,
        })
        .await
        .unwrap();

    state.set_intercept_mode(InterceptMode::Request).await;

    // Listen for the pending intercept so we can resolve it with an
    // edit that changes the path.
    let queue = state.intercept_queue().clone();
    let editor = tokio::spawn(async move {
        let mut rx = queue.subscribe();
        let pending = rx.recv().await.expect("pending recv");
        // Replace the request line's path with `/rewritten`. The raw
        // bytes come back base64-encoded; decode, rewrite, re-encode.
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let bytes = B64.decode(pending.raw_bytes_base64.as_bytes()).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        let edited = wire.replacen("/original", "/rewritten", 1);
        queue
            .resolve(
                pending.id,
                InterceptVerdict::ForwardEdited {
                    bytes: edited.into_bytes(),
                },
            )
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let wire = format!(
        "GET http://{upstream_addr}/original HTTP/1.1\r\n\
         Host: {upstream_addr}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    client.write_all(wire.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    editor.await.unwrap();
    let raw = String::from_utf8_lossy(&buf);
    assert!(
        raw.contains("x-echo-path: /rewritten"),
        "upstream didn't see the edited path: {raw:?}"
    );

    state.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn intercept_drop_returns_502() {
    let tmp = tmpdir();
    let ca = Authority::load_or_generate(CaConfig::for_dir(tmp.join("ca"))).unwrap();
    let db = ProxyDb::open(tmp.join("proxy.sqlite")).unwrap();
    let state = Arc::new(ProxyState::new(Arc::new(ca), Arc::new(db)));

    let upstream_addr = echo_upstream().await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    state
        .start(ProxyConfig {
            listen: proxy_addr,
            note: None,
        })
        .await
        .unwrap();
    state.set_intercept_mode(InterceptMode::Request).await;

    let queue = state.intercept_queue().clone();
    let dropper = tokio::spawn(async move {
        let mut rx = queue.subscribe();
        let pending = rx.recv().await.unwrap();
        queue.resolve(pending.id, InterceptVerdict::Drop).unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let wire = format!(
        "GET http://{upstream_addr}/x HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
    );
    client.write_all(wire.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    dropper.await.unwrap();
    let raw = String::from_utf8_lossy(&buf);
    assert!(raw.starts_with("HTTP/1.1 502"), "expected 502, got: {raw:?}");

    state.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_sends_request_via_core_client_and_records_child() {
    use corvex_proxy::{run_replay, ExchangeOrigin, ReplayInput};

    let tmp = tmpdir();
    let ca = Authority::load_or_generate(CaConfig::for_dir(tmp.join("ca"))).unwrap();
    let db = ProxyDb::open(tmp.join("proxy.sqlite")).unwrap();
    let state = Arc::new(ProxyState::new(Arc::new(ca), Arc::new(db)));

    let upstream_addr = echo_upstream().await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    drop(listener);
    let session = state
        .start(ProxyConfig {
            listen: proxy_addr,
            note: None,
        })
        .await
        .unwrap();

    // Build a synthetic base request that points at the upstream.
    let mut base = corvex_core::http::request::Request::new(
        &upstream_addr.ip().to_string(),
        upstream_addr.port(),
        "GET",
        "/base",
    );
    base.headers.insert("Connection".into(), "close".into());

    let exchange = run_replay(
        state.upstream_client(),
        ReplayInput {
            session_id: session,
            base: base.clone(),
            base_id: corvex_proxy::ExchangeId::new(),
            edited_bytes: None,
        },
    )
    .await
    .expect("replay");

    assert_eq!(exchange.response.as_ref().map(|r| r.status), Some(200));
    assert!(matches!(exchange.origin, ExchangeOrigin::Replay { .. }));

    state.record_exchange(exchange);
    // Give the batched writer a tick — actually replay goes through
    // `record_exchange` which writes synchronously, so the row should
    // already be there.
    let rows = state
        .db()
        .list_exchanges(&session, 10, 0)
        .expect("list exchanges");
    assert!(
        rows.iter().any(|r| r.origin_kind == "replay"),
        "no replay row persisted"
    );

    state.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(&tmp);
}
