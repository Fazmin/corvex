use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

/// MySQL / MariaDB greeting packet.
///
/// Wire format (authored from the MySQL Client/Server Protocol public spec):
///   3-byte little-endian payload length
///   1-byte sequence id
///   payload:
///     protocol version (1 byte)
///     server version (null-terminated string)  ← what we extract
///     thread id, auth-plugin-data-part-1, filler, capability flags, ...
///
/// We read the first ~1 KB (server versions are always under 256 bytes),
/// strip the 4-byte MySQL header, skip the protocol-version byte, then
/// read up to the first NUL byte as the version banner. That banner is
/// fed into the `mysql.greeting` Recog set for product+version+CPE.
#[derive(Default)]
pub struct MySqlProbe;

const PORTS: &[u16] = &[3306, 33060];

#[async_trait]
impl Probe for MySqlProbe {
    fn id(&self) -> &'static str {
        "mysql_greeting"
    }
    fn rarity(&self) -> u8 {
        2
    }
    fn matches_port(&self, port: u16, over_tls: bool) -> bool {
        !over_tls && PORTS.contains(&port)
    }
    fn requires_tls(&self) -> TlsRequirement {
        TlsRequirement::Plain
    }
    fn fingerprint_sets(&self) -> &'static [&'static str] {
        &["mysql.greeting"]
    }

    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence> {
        let mut stream = ctx.connector.connect_plain().await?;
        let mut buf = vec![0u8; 1024];
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
            if total >= 64 {
                break;
            }
        }
        buf.truncate(total);

        let version = extract_version(&buf).unwrap_or_default();
        let response_bytes = version.as_bytes().to_vec();

        let mut multi = Vec::new();
        if !response_bytes.is_empty() {
            multi.push(("mysql.greeting".to_string(), response_bytes.clone()));
        }

        Ok(Evidence {
            service_hint: Some("mysql".to_string()),
            response: response_bytes,
            tls_meta: None,
            jarm: None,
            multi_banner: multi,
        })
    }
}

fn extract_version(buf: &[u8]) -> Option<String> {
    // Minimum packet: 4-byte header + 1 protocol version + at least 1 byte.
    if buf.len() < 6 {
        return None;
    }
    // Skip header (3 bytes length + 1 byte seq) + protocol version byte.
    let start = 5;
    let end = buf[start..].iter().position(|&b| b == 0).map(|p| start + p)?;
    let raw = &buf[start..end];
    let s = std::str::from_utf8(raw).ok()?;
    Some(s.to_string())
}
