//! TLS helpers built on the `openssl` crate directly so we can negotiate
//! legacy ciphers/protocols for fingerprinting old servers.

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use crate::error::{CorvexError, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SslInfo {
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_alt_names: Vec<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
}

/// Build a permissive SslConnector: verify disabled, legacy ciphers allowed.
/// This matches a vulnerability scanner's needs, not a browser's.
pub fn permissive_connector() -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| CorvexError::Tls(format!("SslConnector::builder: {e}")))?;
    builder.set_verify(SslVerifyMode::NONE);
    // Allow everything the local OpenSSL build supports.
    let _ = builder.set_cipher_list("ALL:@SECLEVEL=0");
    Ok(builder.build())
}

pub fn extract_info(cert: Option<&X509>, cipher: Option<&str>, proto: Option<&str>) -> SslInfo {
    let mut info = SslInfo {
        protocol: proto.map(|s| s.to_string()),
        cipher: cipher.map(|s| s.to_string()),
        ..Default::default()
    };
    if let Some(c) = cert {
        info.cert_subject = Some(format!("{:?}", c.subject_name()));
        info.cert_issuer = Some(format!("{:?}", c.issuer_name()));
        if let Some(san) = c.subject_alt_names() {
            info.cert_alt_names = san
                .iter()
                .filter_map(|n| n.dnsname().map(|s| s.to_string()))
                .collect();
        }
        info.cert_not_before = Some(c.not_before().to_string());
        info.cert_not_after = Some(c.not_after().to_string());
    }
    info
}
