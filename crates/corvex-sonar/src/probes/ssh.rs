use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

const SSH_PORTS: &[u16] = &[22, 2222, 22222];

#[derive(Default)]
pub struct SshProbe;

#[async_trait]
impl Probe for SshProbe {
    fn id(&self) -> &'static str {
        "ssh_banner"
    }
    fn rarity(&self) -> u8 {
        1
    }
    fn matches_port(&self, port: u16, _over_tls: bool) -> bool {
        SSH_PORTS.contains(&port)
    }
    fn requires_tls(&self) -> TlsRequirement {
        TlsRequirement::Plain
    }
    fn fingerprint_sets(&self) -> &'static [&'static str] {
        &["ssh.banner"]
    }

    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence> {
        let mut stream = ctx.connector.connect_plain().await?;
        let mut buf = vec![0u8; 512];
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
            if buf[..total].windows(2).any(|w| w == b"\r\n") {
                break;
            }
            if total >= buf.len() {
                break;
            }
        }
        buf.truncate(total);

        Ok(Evidence {
            service_hint: Some("ssh".to_string()),
            response: buf,
            tls_meta: None,
            jarm: None,
            multi_banner: Vec::new(),
        })
    }
}
