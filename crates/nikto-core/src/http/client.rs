//! HTTP client — raw TCP + OpenSSL for TLS, direct HTTP/1.x wire reads.
//!
//! We deliberately bypass hyper's request builder because Nikto sends
//! malformed requests and unusual methods (PROPFIND, SEARCH, arbitrary
//! verbs), and needs raw access to the response bytes.

use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use openssl::ssl::Ssl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_openssl::SslStream;

use crate::error::{NiktoError, Result};
use crate::http::request::Request;
use crate::http::response::Response;
use crate::http::tls;
use crate::state::GlobalState;

pub struct HttpClient {
    state: Arc<GlobalState>,
    default_timeout: Duration,
}

impl HttpClient {
    pub fn new(state: Arc<GlobalState>, timeout_secs: u64) -> Self {
        Self {
            state,
            default_timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Send a single HTTP/1.x request over TCP (+optional TLS) and return
    /// the full parsed response. Counters are updated.
    pub async fn send(&self, req: &Request) -> Result<Response> {
        let dur = Duration::from_secs(req.timeout_secs.max(1));
        let res = timeout(dur, self.do_send(req)).await;
        self.state.incr_request();
        match res {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => {
                self.state.incr_error();
                Err(e)
            }
            Err(_) => {
                self.state.incr_error();
                Err(NiktoError::Http(format!(
                    "timeout after {}s: {} {}",
                    req.timeout_secs, req.method, req.uri
                )))
            }
        }
    }

    async fn do_send(&self, req: &Request) -> Result<Response> {
        let addr = format!("{}:{}", req.host, req.port);
        let sock_addr = addr
            .to_socket_addrs()
            .map_err(|e| NiktoError::Http(format!("resolve {addr}: {e}")))?
            .next()
            .ok_or_else(|| NiktoError::Http(format!("no addr for {addr}")))?;

        let tcp = TcpStream::connect(sock_addr)
            .await
            .map_err(|e| NiktoError::Http(format!("connect {addr}: {e}")))?;

        if req.ssl {
            let connector = tls::permissive_connector()?;
            let ssl = Ssl::new(connector.context())
                .map_err(|e| NiktoError::Tls(e.to_string()))?;
            let mut stream = SslStream::new(ssl, tcp)
                .map_err(|e| NiktoError::Tls(e.to_string()))?;
            Pin::new(&mut stream)
                .connect()
                .await
                .map_err(|e| NiktoError::Tls(format!("handshake: {e}")))?;
            exchange(&mut stream, req).await
        } else {
            let mut tcp = tcp;
            exchange(&mut tcp, req).await
        }
    }

    pub fn state(&self) -> &Arc<GlobalState> {
        &self.state
    }

    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }
}

async fn exchange<S>(stream: &mut S, req: &Request) -> Result<Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let wire = req.to_wire();
    stream
        .write_all(&wire)
        .await
        .map_err(|e| NiktoError::Http(format!("write: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| NiktoError::Http(format!("flush: {e}")))?;

    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    // Read until EOF (we're using Connection: close) or limit.
    const MAX_RESP: usize = 4 * 1024 * 1024; // 4 MiB
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= MAX_RESP {
                    break;
                }
            }
            Err(e) => return Err(NiktoError::Http(format!("read: {e}"))),
        }
    }

    Response::parse(&buf).map_err(NiktoError::Http)
}
