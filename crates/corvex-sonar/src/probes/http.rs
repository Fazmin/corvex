use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8008, 8081, 8180, 8888];
const HTTP_TLS_PORTS: &[u16] = &[443, 8443, 9443, 4443];

#[derive(Default)]
pub struct HttpProbe;

#[async_trait]
impl Probe for HttpProbe {
    fn id(&self) -> &'static str {
        "http_get"
    }
    fn rarity(&self) -> u8 {
        1
    }
    fn matches_port(&self, port: u16, over_tls: bool) -> bool {
        if over_tls {
            HTTP_TLS_PORTS.contains(&port) || HTTP_PORTS.contains(&port)
        } else {
            HTTP_PORTS.contains(&port)
        }
    }
    fn requires_tls(&self) -> TlsRequirement {
        TlsRequirement::Either
    }
    fn fingerprint_sets(&self) -> &'static [&'static str] {
        &["http_header.server"]
    }

    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence> {
        let mut stream = if ctx.over_tls {
            ctx.connector.connect_tls().await?.0
        } else {
            ctx.connector.connect_plain().await?
        };

        let host = &ctx.target.host;
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Corvex/1.0\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        let mut buf = vec![0u8; 8192];
        let mut total = 0usize;
        let read_budget = Duration::from_millis(4000);
        loop {
            let n = match timeout(read_budget, stream.read(&mut buf[total..])).await {
                Ok(Ok(n)) => n,
                _ => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            if total >= buf.len() {
                break;
            }
        }
        buf.truncate(total);

        let server_line = extract_header(&buf, b"Server:");
        let mut multi = Vec::new();
        if let Some(line) = server_line {
            multi.push(("http_header.server".to_string(), line.into_bytes()));
        }

        Ok(Evidence {
            service_hint: Some("http".to_string()),
            response: buf,
            tls_meta: None,
            jarm: None,
            multi_banner: multi,
        })
    }
}

fn extract_header(resp: &[u8], name: &[u8]) -> Option<String> {
    let body = resp;
    let lower_name = name.to_ascii_lowercase();
    let mut start = 0usize;
    while start < body.len() {
        let end = match memchr_crlf(body, start) {
            Some(e) => e,
            None => break,
        };
        let line = &body[start..end];
        if line.len() >= name.len() {
            let head = &line[..name.len()].to_ascii_lowercase();
            if head == &lower_name {
                let val = &line[name.len()..];
                let val_str = std::str::from_utf8(val).ok()?.trim();
                return Some(val_str.to_string());
            }
        }
        if line.is_empty() {
            break;
        }
        start = end + 2;
    }
    None
}

fn memchr_crlf(b: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < b.len() {
        if b[i] == b'\r' && b[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}
