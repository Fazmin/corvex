use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// PostgreSQL detection probe.
///
/// Protocol approach (authored from the PostgreSQL v3 frontend/backend
/// protocol public spec):
///   Send a v3 StartupMessage targeting a bogus database/user. The server
///   responds with an ErrorResponse (tag 'E') describing why the startup
///   failed — the presence of that response shape reveals PostgreSQL, and
///   the error text often includes the server banner.
///
/// We parse the first ErrorResponse payload into a plaintext string and
/// feed it to the `postgres.error` Recog set. If the connection is dropped
/// without a response we still mark the service as postgres because no
/// other common protocol matches this startup packet on this port.
#[derive(Default)]
pub struct PostgresProbe;

const PORTS: &[u16] = &[5432, 5433];

#[async_trait]
impl Probe for PostgresProbe {
    fn id(&self) -> &'static str {
        "postgres_startup"
    }
    fn rarity(&self) -> u8 {
        3
    }
    fn matches_port(&self, port: u16, over_tls: bool) -> bool {
        !over_tls && PORTS.contains(&port)
    }
    fn requires_tls(&self) -> TlsRequirement {
        TlsRequirement::Plain
    }
    fn fingerprint_sets(&self) -> &'static [&'static str] {
        &["postgres.error"]
    }

    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence> {
        let mut stream = ctx.connector.connect_plain().await?;

        // StartupMessage for PostgreSQL protocol v3:
        //   int32 total length
        //   int32 protocol version = 196608 (0x00030000)
        //   key-value pairs terminated by an extra NUL byte
        let body = b"user\0corvex\0database\0corvex\0\0";
        let total_len = (body.len() + 8) as u32;
        let mut msg = Vec::with_capacity(total_len as usize);
        msg.extend_from_slice(&total_len.to_be_bytes());
        msg.extend_from_slice(&0x00030000u32.to_be_bytes());
        msg.extend_from_slice(body);

        stream.write_all(&msg).await?;

        let mut buf = vec![0u8; 2048];
        let mut total = 0usize;
        let budget = Duration::from_millis(3000);
        loop {
            let n = match timeout(budget, stream.read(&mut buf[total..])).await {
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

        let error_text = parse_error_response(&buf);
        let response_bytes: Vec<u8> = error_text
            .clone()
            .map(|s| s.into_bytes())
            .unwrap_or_else(|| buf.clone());

        let mut multi = Vec::new();
        if let Some(text) = error_text {
            multi.push(("postgres.error".to_string(), text.into_bytes()));
        }

        Ok(Evidence {
            service_hint: Some("postgresql".to_string()),
            response: response_bytes,
            tls_meta: None,
            jarm: None,
            multi_banner: multi,
        })
    }
}

fn parse_error_response(buf: &[u8]) -> Option<String> {
    // Look for a message beginning with tag 'E' (ErrorResponse).
    if buf.is_empty() || buf[0] != b'E' {
        return None;
    }
    if buf.len() < 5 {
        return None;
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let end = (1 + len).min(buf.len());
    let mut payload = &buf[5..end];
    let mut out = String::new();
    // Fields are sequences of: 1-byte code + null-terminated string.
    // Code 'M' is the primary human-readable message.
    while let Some(&code) = payload.first() {
        if code == 0 {
            break;
        }
        let after = &payload[1..];
        let term = after.iter().position(|&b| b == 0)?;
        let text = std::str::from_utf8(&after[..term]).ok()?;
        if code == b'M' || code == b'C' || code == b'D' {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(text);
        }
        payload = &after[term + 1..];
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}
