use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// RDP detection via X.224 Connection Request with RDP Negotiation Request.
///
/// Authored from MS-RDPBCGR public spec. Port 3389 receiving an X.224
/// CC-PDU confirms RDP; the Negotiation Response bytes indicate whether
/// NLA / RDP / TLS security is supported.
#[derive(Default)]
pub struct RdpProbe;

const PORTS: &[u16] = &[3389];

#[async_trait]
impl Probe for RdpProbe {
    fn id(&self) -> &'static str {
        "rdp_x224"
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
        &[]
    }

    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence> {
        let mut stream = ctx.connector.connect_plain().await?;

        // TPKT header (version=3, reserved=0, total length=19) +
        // X.224 Connection Request (len=14, CR-CDT=0xE0, dst/src refs=0, class=0) +
        // RDP Negotiation Request (type=1, flags=0, len=8, requestedProtocols=0).
        let x224_cr: &[u8] = &[
            0x03, 0x00, 0x00, 0x13,
            0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        stream.write_all(x224_cr).await?;

        let mut buf = vec![0u8; 256];
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

        let is_rdp = buf.len() >= 5 && buf[0] == 0x03 && buf[1] == 0x00;
        let service_hint = if is_rdp { Some("rdp".to_string()) } else { None };

        Ok(Evidence {
            service_hint,
            response: buf,
            tls_meta: None,
            jarm: None,
            multi_banner: Vec::new(),
        })
    }
}
