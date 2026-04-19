use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// SMB detection probe.
///
/// Sends an SMB2 NEGOTIATE packet (dialect 0x0202, the lowest SMB2) and
/// reads the response. Any SMB2 response confirms the service; some
/// implementations leak OS/server identity in later fields.
///
/// Payload authored from the public MS-SMB2 specification. We do not
/// complete negotiation — the handshake is closed immediately after the
/// first server reply.
#[derive(Default)]
pub struct SmbProbe;

const PORTS: &[u16] = &[445, 139];

#[async_trait]
impl Probe for SmbProbe {
    fn id(&self) -> &'static str {
        "smb_negotiate"
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

        // NetBIOS Session Service header: type=0 + 3-byte big-endian length.
        // Followed by SMB2 NEGOTIATE request (StructureSize=36, DialectCount=1,
        // SecurityMode=signing-enabled, Dialect=SMB 2.0.2).
        let smb2_negotiate: &[u8] = &[
            0x00, 0x00, 0x00, 0x54, // NBSS header, 84-byte payload
            0xFE, 0x53, 0x4D, 0x42, // SMB2 magic ("\xfeSMB")
            0x40, 0x00,             // Header StructureSize
            0x00, 0x00, 0x00, 0x00, // CreditCharge + ChannelSequence
            0x00, 0x00,             // Reserved
            0x00, 0x00,             // Command = NEGOTIATE (0)
            0x00, 0x00, 0x00, 0x00, // CreditRequested + Flags
            0x00, 0x00, 0x00, 0x00, // NextCommand
            0x00, 0x00, 0x00, 0x00, // MessageId lo
            0x00, 0x00, 0x00, 0x00, // MessageId hi
            0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x00, 0x00, // TreeId
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x24, 0x00,             // StructureSize = 36
            0x01, 0x00,             // DialectCount = 1
            0x01, 0x00,             // SecurityMode
            0x00, 0x00,             // Reserved
            0x00, 0x00, 0x00, 0x00, // Capabilities
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStart+ContextCount+Reserved
            0x02, 0x02,             // Dialect 0x0202
        ];

        stream.write_all(smb2_negotiate).await?;

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
            if total >= 256 {
                break;
            }
        }
        buf.truncate(total);

        let is_smb = buf.len() >= 8 && &buf[4..8] == b"\xFESMB";
        let service_hint = if is_smb { Some("smb".to_string()) } else { None };

        Ok(Evidence {
            service_hint,
            response: buf,
            tls_meta: None,
            jarm: None,
            multi_banner: Vec::new(),
        })
    }
}
