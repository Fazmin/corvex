use crate::probe::{Probe, ProbeCtx};
use crate::types::{Evidence, TlsRequirement};
use async_trait::async_trait;

/// Scripted TLS probe: performs a full rustls handshake (through the connector)
/// and reports a synthetic banner describing the negotiated parameters.
///
/// Used by the engine's TLS-first phase; not a port-targeted probe.
#[derive(Default)]
pub struct TlsProbe;

#[async_trait]
impl Probe for TlsProbe {
    fn id(&self) -> &'static str {
        "tls_handshake"
    }
    fn rarity(&self) -> u8 {
        1
    }
    fn matches_port(&self, _port: u16, _over_tls: bool) -> bool {
        false
    }
    fn requires_tls(&self) -> TlsRequirement {
        TlsRequirement::Tls
    }
    fn fingerprint_sets(&self) -> &'static [&'static str] {
        &[]
    }

    async fn run(&self, ctx: &mut ProbeCtx<'_>) -> anyhow::Result<Evidence> {
        let (_stream, meta) = ctx.connector.connect_tls().await?;
        let alpn_hint = match meta.alpn.as_deref() {
            Some("h2") | Some("http/1.1") => Some("http".to_string()),
            _ => None,
        };
        let banner = format!(
            "tls version={:?} cipher={:?} alpn={:?}",
            meta.version, meta.cipher, meta.alpn
        );
        Ok(Evidence {
            service_hint: alpn_hint,
            response: banner.into_bytes(),
            tls_meta: Some(meta),
            jarm: None,
            multi_banner: Vec::new(),
        })
    }
}
