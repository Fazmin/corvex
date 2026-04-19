use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsRequirement {
    Plain,
    Tls,
    Either,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsMeta {
    pub version: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub sni_used: Option<String>,
    pub cert_subjects: Vec<String>,
    pub cert_issuers: Vec<String>,
    pub cert_sans: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub service_hint: Option<String>,
    pub response: Vec<u8>,
    pub tls_meta: Option<TlsMeta>,
    pub jarm: Option<String>,
    pub multi_banner: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeMatch {
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os_product: Option<String>,
    pub os_version: Option<String>,
    pub cpe: Vec<String>,
    pub probe_id: String,
    pub soft: bool,
    pub over_tls: bool,
    pub tls: Option<TlsMeta>,
    pub jarm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    Rapid,
    Deep,
}

impl Default for ScanMode {
    fn default() -> Self {
        Self::Rapid
    }
}

impl ScanMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rapid => "rapid",
            Self::Deep => "deep",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ScanTuning {
    pub connect_timeout_ms: u64,
    pub concurrency: usize,
    pub per_host_concurrency: usize,
    pub probe_budget_ms: u64,
    pub tls_handshake: bool,
    pub run_probes: bool,
}

impl ScanTuning {
    pub fn defaults_for(mode: ScanMode) -> Self {
        match mode {
            ScanMode::Rapid => Self {
                connect_timeout_ms: 300,
                concurrency: 2000,
                per_host_concurrency: 500,
                probe_budget_ms: 0,
                tls_handshake: false,
                run_probes: false,
            },
            ScanMode::Deep => Self {
                connect_timeout_ms: 2500,
                concurrency: 256,
                per_host_concurrency: 64,
                probe_budget_ms: 4000,
                tls_handshake: true,
                run_probes: true,
            },
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SonarOpts {
    pub jarm: bool,
    pub extra_probe_files: Vec<String>,
}

pub struct ProbeTarget {
    pub host: String,
    pub ip: IpAddr,
    pub port: u16,
    pub deadline: Instant,
}
