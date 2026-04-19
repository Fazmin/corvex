use crate::probe::{AsyncReadWrite, Connector, ProbeStream};
use crate::types::{ProbeTarget, TlsMeta};
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, ServerName as PkiServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &PkiServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

fn client_config() -> Arc<ClientConfig> {
    static CFG: OnceCell<Arc<ClientConfig>> = OnceCell::new();
    CFG.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("safe default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny))
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

pub struct TcpConnector {
    target: ProbeTarget,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

impl TcpConnector {
    pub fn new(target: ProbeTarget, connect_timeout_ms: u64) -> Self {
        Self {
            target,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            handshake_timeout: Duration::from_millis(1500),
        }
    }

    async fn connect_raw(&self) -> anyhow::Result<TcpStream> {
        let addr = SocketAddr::new(self.target.ip, self.target.port);
        let s = timeout(self.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::anyhow!("connect timeout"))??;
        Ok(s)
    }

    fn server_name(&self) -> PkiServerName<'static> {
        PkiServerName::try_from(self.target.host.clone())
            .or_else(|_| PkiServerName::try_from("localhost".to_string()))
            .expect("literal 'localhost' is always a valid ServerName")
    }
}

#[async_trait]
impl Connector for TcpConnector {
    async fn connect_plain(&self) -> anyhow::Result<ProbeStream> {
        let s = self.connect_raw().await?;
        let boxed: Box<dyn AsyncReadWrite> = Box::new(s);
        Ok(Box::into_pin(boxed))
    }

    async fn connect_tls(&self) -> anyhow::Result<(ProbeStream, TlsMeta)> {
        let tcp = self.connect_raw().await?;
        let connector = TlsConnector::from(client_config());
        let name = self.server_name();
        let sni_string = format!("{:?}", name);
        let tls = timeout(self.handshake_timeout, connector.connect(name, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("tls handshake timeout"))??;

        let (_, session) = tls.get_ref();
        let alpn = session
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());
        let proto_version = session
            .protocol_version()
            .map(|v| format!("{:?}", v));
        let cipher = session
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()));
        let peer_certs: Vec<CertificateDer<'static>> = session
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.clone().into_owned()).collect())
            .unwrap_or_default();
        let cert_subjects = peer_certs
            .iter()
            .map(|c| hex_fingerprint(c.as_ref()))
            .collect();

        let meta = TlsMeta {
            version: proto_version,
            cipher,
            alpn,
            sni_used: Some(sni_string),
            cert_subjects,
            cert_issuers: Vec::new(),
            cert_sans: Vec::new(),
        };

        let boxed: Box<dyn AsyncReadWrite> = Box::new(tls);
        Ok((Box::into_pin(boxed), meta))
    }
}

fn hex_fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(der);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
