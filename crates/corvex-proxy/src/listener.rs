//! MITM listener.
//!
//! A hyper HTTP/1 server binds the listen address and handles two kinds
//! of client requests:
//!
//! * **Plain HTTP**: the target is reachable via absolute-form URI on
//!   the request line (`GET http://host/path HTTP/1.1`). We rewrite
//!   into origin-form, forward via the existing `corvex-core`
//!   HTTP client, capture the exchange, and relay the response back.
//!
//! * **HTTPS via CONNECT**: the client issues
//!   `CONNECT host:port HTTP/1.1`, we reply `200 Connection
//!   Established`, hijack the upgraded TCP byte stream, terminate TLS
//!   against the client using a locally-signed leaf cert for the
//!   requested SNI, then run another HTTP/1 server on that inner
//!   stream. Every inner request is forwarded upstream over TLS and
//!   the exchange is captured.
//!
//! Both paths feed the same [`ExchangeWriter`] + broadcast channel so
//! the UI layer can't tell them apart.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request as HyperRequest, Response as HyperResponse, StatusCode};
use hyper_util::rt::TokioIo;
use indexmap::IndexMap;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use corvex_core::http::{client::HttpClient, request::Request as CoreRequest, response::Response as CoreResponse};
use corvex_core::state::GlobalState;

use base64::Engine;

use crate::ca::Authority;
use crate::exchange::{Exchange, ExchangeOrigin, InterceptMarks, ScopeDecision, SessionId};
use crate::intercept::{
    InterceptMode, InterceptPhase, InterceptQueue, InterceptVerdict, PendingIntercept,
    INTERCEPT_TIMEOUT,
};
use crate::parser::parse_request;
use crate::scope::ScopeRules;
use crate::writer::ExchangeWriter;

/// Runtime context shared by every task the listener spawns.
pub(crate) struct ListenerCtx {
    pub authority: Arc<Authority>,
    pub session_id: SessionId,
    pub scope: Arc<tokio::sync::RwLock<ScopeRules>>,
    pub intercept_mode: Arc<tokio::sync::RwLock<InterceptMode>>,
    pub intercept_queue: InterceptQueue,
    pub writer: ExchangeWriter,
    pub broadcast: broadcast::Sender<Exchange>,
    pub captured: Arc<AtomicU64>,
    pub upstream: Arc<HttpClient>,
    pub ws_sink: crate::ws::FrameSink,
}

/// Bind the listener to `listen` and serve until `cancel` fires. Returns
/// once the listener loop exits. Panics from accept are logged but not
/// propagated — a single bad handshake shouldn't kill the session.
pub(crate) async fn serve(
    listen: SocketAddr,
    ctx: Arc<ListenerCtx>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let tcp = TcpListener::bind(listen).await?;
    tracing::info!(target: "proxy", "listener bound on {}", listen);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(target: "proxy", "listener cancelled");
                return Ok(());
            }
            accept = tcp.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        tracing::debug!(target: "proxy", "accepted connection from {peer}");
                        let ctx = ctx.clone();
                        let cancel = cancel.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_conn(stream, peer, ctx, cancel).await {
                                tracing::warn!(target: "proxy", "conn {peer} ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(target: "proxy", "accept error: {e}");
                    }
                }
            }
        }
    }
}

async fn serve_conn(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req: HyperRequest<Incoming>| {
        let ctx = ctx.clone();
        let cancel = cancel.clone();
        async move { handle_top(req, peer, ctx, cancel).await }
    });
    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(io, service)
        .with_upgrades()
        .await?;
    Ok(())
}

async fn handle_top(
    req: HyperRequest<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    cancel: CancellationToken,
) -> hyper::Result<HyperResponse<Full<Bytes>>> {
    tracing::debug!(
        target: "proxy",
        "incoming {} {} from {}",
        req.method(),
        req.uri(),
        peer
    );
    if req.method() == Method::CONNECT {
        match handle_connect(req, peer, ctx, cancel).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::warn!(target: "proxy", "CONNECT failed: {e}");
                Ok(text_response(StatusCode::BAD_GATEWAY, "CONNECT failed"))
            }
        }
    } else {
        match handle_plain(req, peer, ctx, false).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::warn!(target: "proxy", "plain HTTP failed: {e}");
                Ok(text_response(StatusCode::BAD_GATEWAY, "upstream failed"))
            }
        }
    }
}

/// Handle a plain HTTP request (absolute URI on the request line).
///
/// `inner_https` is true when this handler is running inside a TLS
/// tunnel established via CONNECT — the scheme becomes `https` and the
/// upstream send must use TLS.
async fn handle_plain(
    req: HyperRequest<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    inner_https: bool,
) -> anyhow::Result<HyperResponse<Full<Bytes>>> {
    // WebSocket upgrade requests need their own code path: the
    // upstream has to see the Upgrade/Connection headers that
    // `to_core_request` strips, and the response has to be a 101 with
    // the upgrade still pending so `hyper::upgrade::on` can hijack the
    // TCP stream and hand it to the WS splicer.
    if is_ws_upgrade_request(req.headers()) {
        return handle_websocket(req, peer, ctx, inner_https).await;
    }

    let (parts, body) = req.into_parts();
    let (body_bytes, req_truncated) = collect_body_capped(body).await?;
    let mut core_req = to_core_request(&parts, body_bytes, inner_https, None)?;

    let scope = {
        let rules = ctx.scope.read().await;
        rules.classify(
            &core_req.host,
            core_req.port,
            &split_path(&core_req.uri),
        )
    };

    let origin = ExchangeOrigin::Proxy { client_addr: peer };
    let mut exchange = Exchange::new(ctx.session_id, origin, core_req.clone(), scope);
    if req_truncated {
        exchange.tags.push("body-truncated".to_string());
    }

    // Intercept: only pause in-scope exchanges. Out-of-scope traffic
    // would otherwise spam the intercept queue with browser background
    // noise.
    if scope == ScopeDecision::InScope {
        let mode = *ctx.intercept_mode.read().await;
        if mode.should_pause_request() {
            match pause_for_verdict(&ctx, &exchange, &core_req, InterceptPhase::Request).await {
                Some(Verdict::Forward) => {
                    exchange.intercepted |= InterceptMarks::REQUEST_PAUSED;
                }
                Some(Verdict::Edited(new_req)) => {
                    exchange.intercepted |=
                        InterceptMarks::REQUEST_PAUSED | InterceptMarks::REQUEST_EDITED;
                    core_req = new_req.clone();
                    exchange.request = new_req;
                    exchange.size_request = exchange.request.body.len() as u64;
                }
                Some(Verdict::Drop) => {
                    exchange.intercepted |= InterceptMarks::REQUEST_PAUSED;
                    exchange.duration_ms = Some(0);
                    exchange.completed_at = Some(time::OffsetDateTime::now_utc());
                    persist_and_broadcast(&ctx, exchange);
                    return Ok(text_response(
                        StatusCode::BAD_GATEWAY,
                        "corvex-proxy: request dropped by user",
                    ));
                }
                None => {
                    // Timeout or parse failure — proceed with the
                    // original request; the warning has already been
                    // logged.
                    exchange.intercepted |= InterceptMarks::REQUEST_PAUSED;
                }
            }
        }
    }

    let started = std::time::Instant::now();
    let result = ctx.upstream.send(&core_req).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(mut resp) => {
            // Cap response body capture at the configured hard limit.
            // We've already received the full body from upstream
            // (corvex-core reads until EOF), so the bytes are in
            // memory; truncating here only affects what gets forwarded
            // to the client and what lands in the exchange log.
            if resp.body.len() > crate::body_store::HARD_CAP {
                tracing::warn!(
                    target: "proxy",
                    "response body {} bytes exceeded {} hard cap — truncating",
                    resp.body.len(),
                    crate::body_store::HARD_CAP
                );
                resp.body.truncate(crate::body_store::HARD_CAP);
                if !exchange.tags.iter().any(|t| t == "body-truncated") {
                    exchange.tags.push("body-truncated".to_string());
                }
            }

            // Response-phase intercept: pause again if the mode demands
            // it and the exchange is in-scope. Out-of-scope traffic is
            // never paused so scope's "log all / gate interactive" rule
            // keeps holding on the response side too.
            if exchange.scope == ScopeDecision::InScope {
                let mode = *ctx.intercept_mode.read().await;
                if mode.should_pause_response() {
                    match pause_for_response_verdict(&ctx, &exchange, &core_req, &resp).await
                    {
                        Some(ResponseVerdict::Forward) => {
                            exchange.intercepted |= InterceptMarks::RESPONSE_PAUSED;
                        }
                        Some(ResponseVerdict::Edited(new_resp)) => {
                            exchange.intercepted |= InterceptMarks::RESPONSE_PAUSED
                                | InterceptMarks::RESPONSE_EDITED;
                            resp = new_resp;
                        }
                        Some(ResponseVerdict::Drop) => {
                            exchange.intercepted |= InterceptMarks::RESPONSE_PAUSED;
                            exchange.response = None;
                            exchange.duration_ms = Some(elapsed_ms);
                            exchange.completed_at =
                                Some(time::OffsetDateTime::now_utc());
                            persist_and_broadcast(&ctx, exchange);
                            return Ok(text_response(
                                StatusCode::BAD_GATEWAY,
                                "corvex-proxy: response dropped by user",
                            ));
                        }
                        None => {
                            exchange.intercepted |= InterceptMarks::RESPONSE_PAUSED;
                        }
                    }
                }
            }

            let hyper_resp = build_hyper_response(&resp);
            exchange.response = Some(resp);
            exchange.duration_ms = Some(elapsed_ms);
            exchange.size_response = exchange
                .response
                .as_ref()
                .map(|r| r.body.len() as u64)
                .unwrap_or(0);
            exchange.completed_at = Some(time::OffsetDateTime::now_utc());
            persist_and_broadcast(&ctx, exchange);
            Ok(hyper_resp)
        }
        Err(e) => {
            tracing::warn!(target: "proxy", "upstream: {e}");
            // Still record the attempt so the UI shows the failed
            // request — duration but no response.
            exchange.duration_ms = Some(elapsed_ms);
            exchange.completed_at = Some(time::OffsetDateTime::now_utc());
            persist_and_broadcast(&ctx, exchange);
            Ok(text_response(
                StatusCode::BAD_GATEWAY,
                &format!("corvex-proxy: {e}"),
            ))
        }
    }
}

/// Handle a CONNECT tunnel: establish TLS to the client using a minted
/// leaf cert, then serve inner HTTP/1 on the decrypted stream.
async fn handle_connect(
    req: HyperRequest<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    cancel: CancellationToken,
) -> anyhow::Result<HyperResponse<Full<Bytes>>> {
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .ok_or_else(|| anyhow::anyhow!("CONNECT without authority"))?;
    let (host, _port) = parse_authority(&target)?;

    // We commit to 200 here; the upgrade only fires after the response
    // is flushed, so any failure inside the spawned task is logged but
    // can't be reflected to the client.
    let host_for_task = host.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) =
                    serve_tls_tunnel(upgraded, host_for_task, peer, ctx, cancel).await
                {
                    tracing::debug!(target: "proxy", "tls tunnel closed: {e}");
                }
            }
            Err(e) => {
                tracing::warn!(target: "proxy", "upgrade failed: {e}");
            }
        }
    });

    Ok(HyperResponse::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .expect("static response"))
}

async fn serve_tls_tunnel(
    upgraded: Upgraded,
    sni: String,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let leaf = ctx.authority.leaf_for(&sni)?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_private_key(&leaf.key)?;
    builder.set_certificate(&leaf.cert)?;
    builder.check_private_key()?;
    let acceptor = builder.build();

    let ssl = Ssl::new(acceptor.context())?;
    let io = TokioIo::new(upgraded);
    let mut ssl_stream = tokio_openssl::SslStream::new(ssl, io)?;
    std::pin::Pin::new(&mut ssl_stream).accept().await?;

    let sni_for_scope = sni.clone();
    let service = service_fn(move |mut req: HyperRequest<Incoming>| {
        // Inside a CONNECT tunnel the client speaks origin-form: the
        // request line is e.g. `GET /foo HTTP/1.1` with no scheme/host.
        // We inject the authority from the CONNECT target so the shared
        // handler can build a complete upstream URI.
        if req.uri().authority().is_none() {
            if let Some(authority) = hyper::http::uri::Authority::try_from(sni_for_scope.as_str()).ok() {
                let mut parts = req.uri().clone().into_parts();
                parts.authority = Some(authority);
                parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
                if let Ok(new_uri) = hyper::Uri::from_parts(parts) {
                    *req.uri_mut() = new_uri;
                }
            }
        }
        let ctx = ctx.clone();
        async move { handle_plain(req, peer, ctx, true).await }
    });

    let tls_io = TokioIo::new(ssl_stream);
    let conn = hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(tls_io, service);

    tokio::select! {
        r = conn => {
            r.map_err(|e| anyhow::anyhow!("inner serve: {e}"))?;
        }
        _ = cancel.cancelled() => {
            tracing::debug!(target: "proxy", "tunnel for {sni} cancelled");
        }
    }
    Ok(())
}

fn to_core_request(
    parts: &hyper::http::request::Parts,
    body: Vec<u8>,
    inner_https: bool,
    forced_host: Option<&str>,
) -> anyhow::Result<CoreRequest> {
    let uri = &parts.uri;
    // Determine scheme, host, port.
    let scheme = uri
        .scheme_str()
        .map(str::to_string)
        .unwrap_or_else(|| if inner_https { "https".into() } else { "http".into() });
    let host = forced_host
        .map(str::to_string)
        .or_else(|| uri.host().map(str::to_string))
        .or_else(|| {
            parts
                .headers
                .get(hyper::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(':').next().unwrap_or(s).to_string())
        })
        .ok_or_else(|| anyhow::anyhow!("request missing host"))?;
    let port = uri.port_u16().unwrap_or_else(|| match scheme.as_str() {
        "https" => 443,
        _ => 80,
    });

    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let mut headers = IndexMap::new();
    for (name, value) in parts.headers.iter() {
        if let Ok(v) = value.to_str() {
            // Strip hop-by-hop headers that must not be forwarded.
            if is_hop_by_hop(name.as_str()) {
                continue;
            }
            headers.insert(name.to_string(), v.to_string());
        }
    }

    // Make sure the Host header matches the target authority; replace
    // any browser-supplied `localhost:8888` with the real target host.
    headers.shift_remove("host");
    headers.shift_remove("Host");
    headers.insert(
        "Host".to_string(),
        if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
            host.clone()
        } else {
            format!("{host}:{port}")
        },
    );

    // corvex-core's raw HTTP client reads responses until EOF, so the
    // upstream must close the socket after the reply. Force
    // `Connection: close` on every forwarded request regardless of what
    // the browser asked for. A future revision can add keep-alive
    // support driven by the client's Content-Length / chunked framing.
    headers.shift_remove("connection");
    headers.shift_remove("Connection");
    headers.insert("Connection".to_string(), "close".to_string());

    Ok(CoreRequest {
        method: parts.method.to_string(),
        uri: path_and_query,
        version: "1.1".to_string(),
        host,
        port,
        ssl: scheme == "https",
        headers,
        body,
        timeout_secs: 30,
    })
}

fn build_hyper_response(resp: &CoreResponse) -> HyperResponse<Full<Bytes>> {
    let mut builder = HyperResponse::builder().status(resp.status);
    for (k, v) in &resp.headers {
        if is_hop_by_hop(k) {
            continue;
        }
        // Hyper rejects Transfer-Encoding on non-streamed bodies; we
        // already have the body fully buffered so we must not propagate
        // it. Same for Content-Length — rebuild based on the actual
        // body length we're about to ship.
        if k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder = builder.header("content-length", resp.body.len());
    builder
        .body(Full::new(Bytes::from(resp.body.clone())))
        .unwrap_or_else(|_| text_response(StatusCode::BAD_GATEWAY, "response rebuild failed"))
}

/// Drain a hyper request body into a `Vec<u8>`, capped at the proxy
/// hard limit. Returns `(bytes, truncated)` — when `truncated` is
/// true the stream carried more than the cap allowed and the trailing
/// bytes were discarded (still drained so the peer doesn't stall).
async fn collect_body_capped(
    body: Incoming,
) -> Result<(Vec<u8>, bool), hyper::Error> {
    use http_body_util::BodyExt;
    let mut body = body;
    let cap = crate::body_store::HARD_CAP;
    let mut out: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(chunk) = frame.into_data() {
            if truncated {
                // Keep draining so the connection closes cleanly.
                continue;
            }
            if out.len() + chunk.len() > cap {
                let take = cap.saturating_sub(out.len());
                out.extend_from_slice(&chunk[..take]);
                truncated = true;
            } else {
                out.extend_from_slice(&chunk);
            }
        }
    }
    Ok((out, truncated))
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
    )
}

fn split_path(uri: &str) -> String {
    uri.split_once('?').map(|(p, _)| p.to_string()).unwrap_or_else(|| uri.to_string())
}

fn parse_authority(s: &str) -> anyhow::Result<(String, u16)> {
    match s.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse()?)),
        None => Ok((s.to_string(), 443)),
    }
}

fn text_response(status: StatusCode, msg: &str) -> HyperResponse<Full<Bytes>> {
    HyperResponse::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("content-length", msg.len())
        .body(Full::new(Bytes::from(msg.to_string())))
        .expect("static response")
}

fn persist_and_broadcast(ctx: &ListenerCtx, mut exchange: Exchange) {
    exchange.intercepted = InterceptMarks::empty();
    if let ScopeDecision::OutOfScope = exchange.scope {
        // Still persisted, but mark the tag so the UI can filter quickly.
        if !exchange.tags.iter().any(|t| t == "out-of-scope") {
            exchange.tags.push("out-of-scope".to_string());
        }
    }
    ctx.captured.fetch_add(1, Ordering::Relaxed);
    // Send to the live stream first so the UI updates before the row is
    // durable. Dropped broadcast slots are fine — persistence is the
    // source of truth for the traffic log.
    let _ = ctx.broadcast.send(exchange.clone());
    ctx.writer.submit(exchange);
}

/// Build an upstream client tuned for proxy use — longer timeout than
/// the scanner default so large downloads don't prematurely abort, but
/// still bounded.
pub(crate) fn build_upstream() -> HttpClient {
    let state = Arc::new(GlobalState::new());
    HttpClient::new(state, 60)
}

/// Internal verdict representation — resolved after re-parsing edited
/// bytes so the caller doesn't have to know about parse failures.
enum Verdict {
    Forward,
    Edited(CoreRequest),
    Drop,
}

/// Same shape as [`Verdict`] but for the response-phase pause, carrying
/// the already-reparsed [`CoreResponse`] if the user edited the bytes.
enum ResponseVerdict {
    Forward,
    Edited(CoreResponse),
    Drop,
}

async fn pause_for_verdict(
    ctx: &Arc<ListenerCtx>,
    exchange: &Exchange,
    current: &CoreRequest,
    phase: InterceptPhase,
) -> Option<Verdict> {
    let snapshot = PendingIntercept {
        id: exchange.id,
        phase,
        method: current.method.clone(),
        host: current.host.clone(),
        port: current.port,
        scheme: if current.ssl { "https".into() } else { "http".into() },
        uri: current.uri.clone(),
        raw_bytes_base64: base64::engine::general_purpose::STANDARD.encode(current.to_wire()),
    };
    let rx = ctx.intercept_queue.pause(snapshot);
    let verdict = match tokio::time::timeout(INTERCEPT_TIMEOUT, rx).await {
        Ok(Ok(v)) => v,
        Ok(Err(_)) => {
            tracing::warn!(target: "proxy", "intercept sender dropped before verdict");
            return None;
        }
        Err(_) => {
            tracing::warn!(
                target: "proxy",
                "intercept {} timed out after {}s — auto-forwarding",
                exchange.id,
                INTERCEPT_TIMEOUT.as_secs()
            );
            return None;
        }
    };
    match verdict {
        InterceptVerdict::Forward => Some(Verdict::Forward),
        InterceptVerdict::Drop => Some(Verdict::Drop),
        InterceptVerdict::ForwardEdited { bytes } => {
            match parse_request(&bytes, &current.host, current.port, current.ssl) {
                Ok(mut edited) => {
                    // Keep the forced Connection: close invariant that
                    // the upstream read loop depends on.
                    edited.headers.shift_remove("connection");
                    edited.headers.shift_remove("Connection");
                    edited
                        .headers
                        .insert("Connection".into(), "close".into());
                    Some(Verdict::Edited(edited))
                }
                Err(e) => {
                    tracing::warn!(
                        target: "proxy",
                        "edited request failed to parse, using original: {e}"
                    );
                    Some(Verdict::Forward)
                }
            }
        }
    }
}

fn is_ws_upgrade_request(headers: &hyper::HeaderMap) -> bool {
    let has_ws_upgrade = headers
        .get_all(hyper::header::UPGRADE)
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| s.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
        });
    let has_upgrade_token = headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| {
                    s.split(',')
                        .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
                })
                .unwrap_or(false)
        });
    has_ws_upgrade && has_upgrade_token
}

/// Upstream byte stream for a WebSocket — either plain TCP or TLS.
/// Boxing a trait object would need two bounds in one type, so we
/// enum-dispatch instead.
enum UpstreamIo {
    Plain(TcpStream),
    Tls(tokio_openssl::SslStream<TcpStream>),
}

impl tokio::io::AsyncRead for UpstreamIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Handle a WebSocket handshake + frame splice. We persist the
/// handshake as a regular [`Exchange`] tagged `websocket` so the UI's
/// traffic list still shows the upgrade, then splice the two byte
/// streams in a background task that decodes frames on the fly.
async fn handle_websocket(
    req: HyperRequest<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ListenerCtx>,
    inner_https: bool,
) -> anyhow::Result<HyperResponse<Full<Bytes>>> {
    use tokio::io::AsyncWriteExt;

    // Derive everything we need for the handshake + logging BEFORE
    // consuming the request — `hyper::upgrade::on` wants to own the
    // request so it can hook the connection's upgrade mechanism.
    let method = req.method().to_string();
    let uri = req.uri().clone();
    let mut headers = IndexMap::<String, String>::new();
    for (k, v) in req.headers().iter() {
        if let Ok(s) = v.to_str() {
            headers.insert(k.to_string(), s.to_string());
        }
    }

    let (host, port) = resolve_host_port(&uri, &headers, inner_https);
    if host.is_empty() {
        return Ok(text_response(
            StatusCode::BAD_REQUEST,
            "corvex-proxy: ws request missing host",
        ));
    }

    let path_and_query = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Rewrite Host to match the upstream authority so the upstream
    // sees the right vhost even if the browser sent the proxy's addr.
    headers.shift_remove("host");
    headers.shift_remove("Host");
    headers.insert(
        "Host".to_string(),
        if (!inner_https && port == 80) || (inner_https && port == 443) {
            host.clone()
        } else {
            format!("{host}:{port}")
        },
    );

    let core_req = CoreRequest {
        method,
        uri: path_and_query,
        version: "1.1".to_string(),
        host: host.clone(),
        port,
        ssl: inner_https,
        headers,
        body: Vec::new(),
        timeout_secs: 30,
    };

    let scope = {
        let rules = ctx.scope.read().await;
        rules.classify(&core_req.host, core_req.port, &split_path(&core_req.uri))
    };

    let origin = ExchangeOrigin::Proxy { client_addr: peer };
    let mut exchange = Exchange::new(ctx.session_id, origin, core_req.clone(), scope);
    exchange.tags.push("websocket".to_string());
    let exchange_id = exchange.id;

    // Open upstream socket + send the handshake request verbatim.
    let mut upstream = match connect_upstream(&host, port, inner_https).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: "proxy", "ws upstream connect: {e}");
            exchange.completed_at = Some(time::OffsetDateTime::now_utc());
            persist_and_broadcast(&ctx, exchange);
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                &format!("corvex-proxy: ws upstream: {e}"),
            ));
        }
    };

    if let Err(e) = upstream.write_all(&core_req.to_wire()).await {
        tracing::warn!(target: "proxy", "ws handshake write: {e}");
        exchange.completed_at = Some(time::OffsetDateTime::now_utc());
        persist_and_broadcast(&ctx, exchange);
        return Ok(text_response(
            StatusCode::BAD_GATEWAY,
            &format!("corvex-proxy: ws write: {e}"),
        ));
    }

    let resp_head = match read_http_head(&mut upstream).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(target: "proxy", "ws upstream head read: {e}");
            exchange.completed_at = Some(time::OffsetDateTime::now_utc());
            persist_and_broadcast(&ctx, exchange);
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                &format!("corvex-proxy: ws head: {e}"),
            ));
        }
    };

    let parsed = corvex_core::http::response::Response::parse(&resp_head)
        .map_err(|e| anyhow::anyhow!("ws response parse: {e}"))?;
    let status = parsed.status;
    let has_extension = parsed.header("sec-websocket-extensions").is_some();
    exchange.response = Some(parsed.clone());
    exchange.completed_at = Some(time::OffsetDateTime::now_utc());

    if status != 101 {
        // Upstream refused the upgrade — relay the response normally.
        let hyper_resp = build_hyper_response(&parsed);
        persist_and_broadcast(&ctx, exchange);
        return Ok(hyper_resp);
    }

    if has_extension {
        exchange.tags.push("ws-extension".to_string());
    }

    // Build the 101 response that hyper will emit before triggering
    // the upgrade future.
    let mut builder = HyperResponse::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in &parsed.headers {
        let keep = matches!(
            k.to_ascii_lowercase().as_str(),
            "upgrade"
                | "connection"
                | "sec-websocket-accept"
                | "sec-websocket-protocol"
                | "sec-websocket-extensions"
                | "sec-websocket-version"
        );
        if keep {
            builder = builder.header(k, v);
        }
    }
    let resp_to_client = builder
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| text_response(StatusCode::BAD_GATEWAY, "ws 101 build failed"));

    let sink = ctx.ws_sink.clone();
    persist_and_broadcast(&ctx, exchange);

    // Register the upgrade future against the original request, then
    // spawn a task that awaits it and hands the bidirectional byte
    // stream to the splicer.
    let upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        match upgrade.await {
            Ok(upgraded) => {
                let client_io = hyper_util::rt::TokioIo::new(upgraded);
                if let Err(e) =
                    crate::ws::splice(client_io, upstream, exchange_id, sink).await
                {
                    tracing::debug!(target: "proxy", "ws splice ended: {e}");
                }
            }
            Err(e) => {
                tracing::warn!(target: "proxy", "ws upgrade failed: {e}");
            }
        }
    });

    Ok(resp_to_client)
}

fn resolve_host_port(
    uri: &hyper::Uri,
    headers: &IndexMap<String, String>,
    inner_https: bool,
) -> (String, u16) {
    let default_port = if inner_https { 443 } else { 80 };

    if let Some(host) = uri.host() {
        let port = uri.port_u16().unwrap_or(default_port);
        return (host.to_string(), port);
    }

    let host_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    if let Some(h) = host_header {
        match h.rsplit_once(':') {
            Some((host, port_s)) => {
                if let Ok(p) = port_s.parse::<u16>() {
                    return (host.to_string(), p);
                }
                return (h.to_string(), default_port);
            }
            None => return (h.to_string(), default_port),
        }
    }
    (String::new(), default_port)
}

/// Open a raw TCP (or TLS) socket to the upstream WebSocket server.
async fn connect_upstream(host: &str, port: u16, tls: bool) -> anyhow::Result<UpstreamIo> {
    let tcp = TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true).ok();
    if !tls {
        return Ok(UpstreamIo::Plain(tcp));
    }
    let connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?.build();
    let mut config = connector.configure()?;
    config.set_use_server_name_indication(true);
    config.set_verify_hostname(false);
    let ssl = config.into_ssl(host)?;
    let mut stream = tokio_openssl::SslStream::new(ssl, tcp)?;
    std::pin::Pin::new(&mut stream).connect().await?;
    Ok(UpstreamIo::Tls(stream))
}

/// Read bytes from `r` until we see `\r\n\r\n`. Returns the header
/// bytes (including terminator). The upstream then yields the first
/// frame's bytes directly — no over-read because we stop exactly at
/// the terminator.
async fn read_http_head<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        let n = r.read(&mut one).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before headers ended",
            ));
        }
        buf.extend_from_slice(&one);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ws response headers exceed 64 KB",
            ));
        }
    }
    Ok(buf)
}

async fn pause_for_response_verdict(
    ctx: &Arc<ListenerCtx>,
    exchange: &Exchange,
    current: &CoreRequest,
    resp: &CoreResponse,
) -> Option<ResponseVerdict> {
    let snapshot = PendingIntercept {
        id: exchange.id,
        phase: InterceptPhase::Response,
        method: current.method.clone(),
        host: current.host.clone(),
        port: current.port,
        scheme: if current.ssl { "https".into() } else { "http".into() },
        uri: current.uri.clone(),
        raw_bytes_base64: base64::engine::general_purpose::STANDARD.encode(resp.to_wire()),
    };
    let rx = ctx.intercept_queue.pause(snapshot);
    let verdict = match tokio::time::timeout(INTERCEPT_TIMEOUT, rx).await {
        Ok(Ok(v)) => v,
        Ok(Err(_)) => {
            tracing::warn!(target: "proxy", "intercept sender dropped before response verdict");
            return None;
        }
        Err(_) => {
            tracing::warn!(
                target: "proxy",
                "response intercept {} timed out after {}s — auto-forwarding",
                exchange.id,
                INTERCEPT_TIMEOUT.as_secs()
            );
            return None;
        }
    };
    match verdict {
        InterceptVerdict::Forward => Some(ResponseVerdict::Forward),
        InterceptVerdict::Drop => Some(ResponseVerdict::Drop),
        InterceptVerdict::ForwardEdited { bytes } => match CoreResponse::parse(&bytes) {
            Ok(edited) => Some(ResponseVerdict::Edited(edited)),
            Err(e) => {
                tracing::warn!(
                    target: "proxy",
                    "edited response failed to parse, using original: {e}"
                );
                Some(ResponseVerdict::Forward)
            }
        },
    }
}
