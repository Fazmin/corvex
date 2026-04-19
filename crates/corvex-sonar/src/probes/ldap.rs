use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// LDAP root-DSE probe.
///
/// Sends an anonymous-bind (BindRequest, version 3) followed by a
/// SearchRequest for the root DSE (base "", scope=baseObject, filter
/// `(objectClass=*)`, attrs={supportedLDAPVersion, vendorName,
/// vendorVersion, dnsHostName}).
///
/// Payload is a BER-encoded, pre-serialised byte sequence authored from
/// RFC 4511. Any LDAPMessage response confirms the service.
#[derive(Default)]
pub struct LdapProbe;

const PORTS: &[u16] = &[389, 3268];
const TLS_PORTS: &[u16] = &[636, 3269];

#[async_trait]
impl Probe for LdapProbe {
    fn id(&self) -> &'static str {
        "ldap_root_dse"
    }
    fn rarity(&self) -> u8 {
        3
    }
    fn matches_port(&self, port: u16, over_tls: bool) -> bool {
        if over_tls {
            TLS_PORTS.contains(&port)
        } else {
            PORTS.contains(&port)
        }
    }
    fn requires_tls(&self) -> TlsRequirement {
        TlsRequirement::Either
    }
    fn fingerprint_sets(&self) -> &'static [&'static str] {
        &["ldap.root_dse"]
    }

    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence> {
        let mut stream = if ctx.over_tls {
            ctx.connector.connect_tls().await?.0
        } else {
            ctx.connector.connect_plain().await?
        };

        // Anonymous BindRequest (LDAPv3): messageID=1.
        // Structure: LDAPMessage { messageID=1, BindRequest { version=3,
        //   name="", authentication=simple("") } }.
        let bind: &[u8] = &[
            0x30, 0x0c,                         // SEQUENCE, length 12
            0x02, 0x01, 0x01,                   // messageID = 1
            0x60, 0x07,                         // [APPLICATION 0] BindRequest
            0x02, 0x01, 0x03,                   // version = 3
            0x04, 0x00,                         // name = ""
            0x80, 0x00,                         // [CONTEXT 0] simple = ""
        ];
        stream.write_all(bind).await?;

        // Read BindResponse — we don't fully parse it, just confirm bytes
        // come back. Errors here still reveal the service.
        let mut header = vec![0u8; 256];
        let budget = Duration::from_millis(3000);
        let n = match timeout(budget, stream.read(&mut header)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        header.truncate(n);

        // SearchRequest for the root DSE.
        // base = "", scope = baseObject(0), derefAliases = neverDerefAliases(0),
        // sizeLimit = 0, timeLimit = 0, typesOnly = FALSE, filter = present "objectClass",
        // attrs = SEQUENCE OF AttributeDescription.
        let search: &[u8] = &[
            0x30, 0x38,                         // SEQUENCE, 56 bytes
            0x02, 0x01, 0x02,                   // messageID = 2
            0x63, 0x33,                         // [APPLICATION 3] SearchRequest, 51 bytes
            0x04, 0x00,                         // baseObject = ""
            0x0a, 0x01, 0x00,                   // scope = baseObject
            0x0a, 0x01, 0x00,                   // derefAliases = neverDerefAliases
            0x02, 0x01, 0x00,                   // sizeLimit = 0
            0x02, 0x01, 0x00,                   // timeLimit = 0
            0x01, 0x01, 0x00,                   // typesOnly = FALSE
            0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            0x30, 0x1c,                         // attrs SEQUENCE, 28 bytes
            0x04, 0x10, b's', b'u', b'p', b'p', b'o', b'r', b't', b'e', b'd', b'L', b'D', b'A', b'P', b'V', b'e', b'r',
            0x04, 0x08, b'v', b'e', b'n', b'd', b'o', b'r', b'N', b'a',
        ];
        if let Err(_) = stream.write_all(search).await {
            // still emit what we got
        }

        let mut rest = vec![0u8; 2048];
        let mut total = 0usize;
        loop {
            let n = match timeout(budget, stream.read(&mut rest[total..])).await {
                Ok(Ok(n)) => n,
                _ => break,
            };
            if n == 0 {
                break;
            }
            total += n;
            if total >= 1536 {
                break;
            }
        }
        rest.truncate(total);

        let mut combined = header;
        combined.extend_from_slice(&rest);

        let is_ldap = !combined.is_empty() && combined[0] == 0x30;
        let service_hint = if is_ldap { Some("ldap".to_string()) } else { None };

        Ok(Evidence {
            service_hint,
            response: combined,
            tls_meta: None,
            jarm: None,
            multi_banner: Vec::new(),
        })
    }
}
