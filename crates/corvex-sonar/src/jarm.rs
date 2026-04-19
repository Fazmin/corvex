//! JARM TLS-stack fingerprinting.
//!
//! JARM sends a fixed sequence of 10 TLS Client Hellos with carefully
//! chosen version/cipher/extension permutations, reads each ServerHello,
//! and distils the (chosen_version, chosen_cipher, extension_fingerprint)
//! tuple from each into a 62-character hash: 30 characters of per-probe
//! cipher/version digest + 32 hex characters of a SHA-256 over the
//! concatenated extension fingerprints.
//!
//! This implementation is written from scratch against the public
//! algorithm description. It constructs raw Client Hellos on the wire
//! (without rustls) so we can control cipher order, extension order,
//! and GREASE values byte-for-byte.

use sha2::{Digest, Sha256};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// A single ServerHello summary used to build the JARM hash.
#[derive(Debug, Clone, Default)]
pub struct ServerHelloSummary {
    /// Negotiated TLS version from the record layer (e.g. 0x0303 = TLS 1.2).
    pub tls_version: Option<u16>,
    /// Negotiated cipher suite (2 bytes).
    pub cipher: Option<u16>,
    /// Hex-encoded SHA-256 of the extension list order (for extension
    /// fingerprint). Empty string when ServerHello is absent or
    /// extensionless (e.g. SSLv3 responses).
    pub extension_digest: String,
}

/// Permutation entry: (tls_version, cipher_set, ext_order, grease, alpn_set).
#[derive(Debug, Clone, Copy)]
struct JarmProbeCfg {
    tls_version: u16,
    cipher_set: CipherSet,
    cipher_order: CipherOrder,
    grease: bool,
    rare_extension_order: bool,
    alpn: AlpnSet,
}

#[derive(Debug, Clone, Copy)]
enum CipherSet {
    All,
    NoForwardSecrecy,
    Tls13Only,
}

#[derive(Debug, Clone, Copy)]
enum CipherOrder {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    Middle,
}

#[derive(Debug, Clone, Copy)]
enum AlpnSet {
    All,
    Rare,
}

const JARM_PROBES: &[JarmProbeCfg] = &[
    JarmProbeCfg { tls_version: 0x0303, cipher_set: CipherSet::All,             cipher_order: CipherOrder::Forward,    grease: false, rare_extension_order: false, alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0303, cipher_set: CipherSet::All,             cipher_order: CipherOrder::Reverse,    grease: false, rare_extension_order: false, alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0303, cipher_set: CipherSet::All,             cipher_order: CipherOrder::TopHalf,    grease: true,  rare_extension_order: true,  alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0303, cipher_set: CipherSet::NoForwardSecrecy,cipher_order: CipherOrder::Forward,    grease: false, rare_extension_order: false, alpn: AlpnSet::Rare },
    JarmProbeCfg { tls_version: 0x0304, cipher_set: CipherSet::Tls13Only,       cipher_order: CipherOrder::Forward,    grease: false, rare_extension_order: false, alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0304, cipher_set: CipherSet::Tls13Only,       cipher_order: CipherOrder::Reverse,    grease: false, rare_extension_order: false, alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0304, cipher_set: CipherSet::Tls13Only,       cipher_order: CipherOrder::Middle,     grease: true,  rare_extension_order: true,  alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0302, cipher_set: CipherSet::All,             cipher_order: CipherOrder::Forward,    grease: false, rare_extension_order: false, alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0301, cipher_set: CipherSet::All,             cipher_order: CipherOrder::Forward,    grease: false, rare_extension_order: false, alpn: AlpnSet::All },
    JarmProbeCfg { tls_version: 0x0300, cipher_set: CipherSet::All,             cipher_order: CipherOrder::BottomHalf, grease: false, rare_extension_order: false, alpn: AlpnSet::All },
];

const CIPHER_ALL: &[u16] = &[
    0x0016, 0x0033, 0x0067, 0x00a3, 0x0039, 0x006b, 0x00a7,
    0x009e, 0x00a2, 0xccaa, 0xc02c, 0xc030, 0xc02b, 0xc02f,
    0xc024, 0xc028, 0xc023, 0xc027, 0xcca9, 0xcca8, 0x009c,
    0x009d, 0x003c, 0x003d, 0x002f, 0x0035, 0x000a,
];

const CIPHER_NO_FS: &[u16] = &[
    0x002f, 0x0035, 0x009c, 0x009d, 0x003c, 0x003d, 0x000a,
];

const CIPHER_TLS13: &[u16] = &[0x1301, 0x1302, 0x1303, 0x1304, 0x1305];

/// Run JARM against the given target. Returns the 62-character hash.
pub async fn jarm_hash_for(
    addr: SocketAddr,
    host: &str,
    per_probe_timeout: Duration,
) -> anyhow::Result<String> {
    let mut summaries = Vec::with_capacity(JARM_PROBES.len());
    for probe in JARM_PROBES {
        let summary = match run_probe(addr, host, probe, per_probe_timeout).await {
            Ok(s) => s,
            Err(_) => ServerHelloSummary::default(),
        };
        summaries.push(summary);
    }
    Ok(jarm_hash(&summaries))
}

async fn run_probe(
    addr: SocketAddr,
    host: &str,
    cfg: &JarmProbeCfg,
    budget: Duration,
) -> io::Result<ServerHelloSummary> {
    let client_hello = build_client_hello(cfg, host);
    let mut stream = timeout(budget, TcpStream::connect(addr))
        .await
        .map_err(io::Error::from)??;
    timeout(budget, stream.write_all(&client_hello))
        .await
        .map_err(io::Error::from)??;

    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    let deadline = tokio::time::Instant::now() + budget;
    while total < buf.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let n = match timeout(remaining, stream.read(&mut buf[total..])).await {
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
    Ok(parse_server_hello(&buf))
}

fn build_client_hello(cfg: &JarmProbeCfg, host: &str) -> Vec<u8> {
    let mut ciphers: Vec<u16> = match cfg.cipher_set {
        CipherSet::All => CIPHER_ALL.to_vec(),
        CipherSet::NoForwardSecrecy => CIPHER_NO_FS.to_vec(),
        CipherSet::Tls13Only => CIPHER_TLS13.to_vec(),
    };
    apply_cipher_order(&mut ciphers, cfg.cipher_order);
    if cfg.grease {
        ciphers.insert(0, 0x0a0a);
    }

    let mut body = Vec::new();
    body.push(0x03);
    body.push(0x03);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x20);
    body.extend_from_slice(&[0u8; 32]);

    let cipher_bytes_len = (ciphers.len() * 2) as u16;
    body.extend_from_slice(&cipher_bytes_len.to_be_bytes());
    for c in &ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }
    body.push(0x01);
    body.push(0x00);

    let ext = build_extensions(cfg, host);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = Vec::new();
    hs.push(0x01);
    hs.extend_from_slice(&u24_len(body.len() as u32));
    hs.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&0x0301u16.to_be_bytes());
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

fn apply_cipher_order(ciphers: &mut Vec<u16>, order: CipherOrder) {
    match order {
        CipherOrder::Forward => {}
        CipherOrder::Reverse => ciphers.reverse(),
        CipherOrder::TopHalf => {
            let mid = ciphers.len() / 2;
            ciphers.drain(mid..);
        }
        CipherOrder::BottomHalf => {
            let mid = ciphers.len() / 2;
            ciphers.drain(..mid);
        }
        CipherOrder::Middle => {
            let mid = ciphers.len() / 2;
            let quarter = ciphers.len() / 4;
            *ciphers = ciphers[quarter..mid + quarter].to_vec();
        }
    }
}

fn build_extensions(cfg: &JarmProbeCfg, host: &str) -> Vec<u8> {
    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();

    if cfg.grease {
        exts.push((0x0a0a, Vec::new()));
    }
    exts.push((0x0000, sni_ext(host)));
    exts.push((0x0017, Vec::new())); // extended_master_secret
    exts.push((0x0001, vec![0x00])); // max_fragment_length
    exts.push((0x000b, vec![0x01, 0x00])); // ec_point_formats
    exts.push((0x000a, supported_groups())); // supported_groups
    exts.push((0x0023, Vec::new())); // session_ticket
    exts.push((0x0010, alpn_ext(cfg.alpn))); // alpn
    exts.push((0x000d, signature_algorithms()));
    exts.push((0x002b, supported_versions(cfg.tls_version)));
    exts.push((0x002d, vec![0x02, 0x01, 0x01])); // psk_key_exchange_modes
    exts.push((0x0033, key_share_ext())); // key_share

    if cfg.rare_extension_order {
        exts.reverse();
    }

    let mut out = Vec::new();
    for (code, body) in exts {
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
    }
    out
}

fn sni_ext(host: &str) -> Vec<u8> {
    let hb = host.as_bytes();
    let inner_len = 3 + hb.len();
    let mut out = Vec::with_capacity(2 + inner_len);
    out.extend_from_slice(&(inner_len as u16).to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&(hb.len() as u16).to_be_bytes());
    out.extend_from_slice(hb);
    out
}

fn supported_groups() -> Vec<u8> {
    let groups: &[u16] = &[
        0x001d, 0x0017, 0x001e, 0x0019, 0x0018,
    ];
    let body_len = (groups.len() * 2) as u16;
    let mut out = Vec::with_capacity(2 + body_len as usize);
    out.extend_from_slice(&body_len.to_be_bytes());
    for g in groups {
        out.extend_from_slice(&g.to_be_bytes());
    }
    out
}

fn alpn_ext(set: AlpnSet) -> Vec<u8> {
    let protos: &[&[u8]] = match set {
        AlpnSet::All => &[b"http/1.1", b"h2"],
        AlpnSet::Rare => &[b"h2c", b"http/0.9"],
    };
    let mut inner = Vec::new();
    for p in protos {
        inner.push(p.len() as u8);
        inner.extend_from_slice(p);
    }
    let mut out = Vec::with_capacity(2 + inner.len());
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

fn signature_algorithms() -> Vec<u8> {
    let sigs: &[u16] = &[
        0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809,
        0x080a, 0x080b, 0x0804, 0x0805, 0x0806,
    ];
    let body_len = (sigs.len() * 2) as u16;
    let mut out = Vec::with_capacity(2 + body_len as usize);
    out.extend_from_slice(&body_len.to_be_bytes());
    for s in sigs {
        out.extend_from_slice(&s.to_be_bytes());
    }
    out
}

fn supported_versions(preferred: u16) -> Vec<u8> {
    let mut list: Vec<u16> = vec![preferred];
    for v in [0x0304, 0x0303, 0x0302, 0x0301, 0x0300] {
        if v != preferred {
            list.push(v);
        }
    }
    let body_len = (list.len() * 2) as u8;
    let mut out = Vec::with_capacity(1 + body_len as usize);
    out.push(body_len);
    for v in list {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

fn key_share_ext() -> Vec<u8> {
    let pubkey = [0x04u8; 32];
    let mut share = Vec::new();
    share.extend_from_slice(&0x001du16.to_be_bytes());
    share.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
    share.extend_from_slice(&pubkey);

    let mut out = Vec::new();
    out.extend_from_slice(&(share.len() as u16).to_be_bytes());
    out.extend_from_slice(&share);
    out
}

fn u24_len(v: u32) -> [u8; 3] {
    [((v >> 16) & 0xff) as u8, ((v >> 8) & 0xff) as u8, (v & 0xff) as u8]
}

fn parse_server_hello(buf: &[u8]) -> ServerHelloSummary {
    // TLS record: type(1) + version(2) + length(2) + payload.
    if buf.len() < 5 || buf[0] != 0x16 {
        return ServerHelloSummary::default();
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let payload_end = 5 + record_len;
    if buf.len() < payload_end.min(5) + 4 {
        return ServerHelloSummary::default();
    }
    let p = &buf[5..buf.len().min(payload_end)];

    // Handshake: type(1) + length(3) + body.
    if p.len() < 4 || p[0] != 0x02 {
        return ServerHelloSummary::default();
    }
    let hs_len = ((p[1] as usize) << 16) | ((p[2] as usize) << 8) | p[3] as usize;
    let hs_end = 4 + hs_len;
    let body = &p[4..p.len().min(hs_end)];

    // ServerHello body:
    //   version(2) + random(32) + session_id_len(1) + session_id +
    //   cipher(2) + comp_method(1) + [extensions_len(2) + extensions]
    if body.len() < 35 {
        return ServerHelloSummary::default();
    }
    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let sid_len = body[34] as usize;
    let after_sid = 35 + sid_len;
    if body.len() < after_sid + 3 {
        return ServerHelloSummary::default();
    }
    let cipher = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]);
    let ext_offset = after_sid + 3;
    let extension_digest = if body.len() >= ext_offset + 2 {
        let ext_len = u16::from_be_bytes([body[ext_offset], body[ext_offset + 1]]) as usize;
        let ext_start = ext_offset + 2;
        let ext_end = (ext_start + ext_len).min(body.len());
        extension_codes_digest(&body[ext_start..ext_end])
    } else {
        String::new()
    };

    ServerHelloSummary {
        tls_version: Some(tls_version),
        cipher: Some(cipher),
        extension_digest,
    }
}

fn extension_codes_digest(exts: &[u8]) -> String {
    let mut codes = Vec::new();
    let mut i = 0;
    while i + 4 <= exts.len() {
        let code = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let len = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        codes.push(format!("{:04x}", code));
        i += 4 + len;
    }
    let joined = codes.join(",");
    let mut hasher = Sha256::new();
    hasher.update(joined.as_bytes());
    let out = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in out.iter() {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Pure-function hash builder. Takes the 10 `ServerHelloSummary` records
/// and produces the canonical 62-character JARM string.
pub fn jarm_hash(summaries: &[ServerHelloSummary]) -> String {
    let mut per_probe: Vec<String> = Vec::with_capacity(10);
    let mut ext_digests: Vec<String> = Vec::with_capacity(10);
    for s in summaries.iter().take(10) {
        let cipher_code = match s.cipher {
            Some(c) => format!("{:04x}", c),
            None => "0000".to_string(),
        };
        let version_code = match s.tls_version {
            Some(v) => format!("{:02x}", (v & 0xff) as u8),
            None => "00".to_string(),
        };
        per_probe.push(format!("{cipher_code}{version_code}"));
        ext_digests.push(if s.extension_digest.is_empty() {
            "0".repeat(64)
        } else {
            s.extension_digest.clone()
        });
    }
    while per_probe.len() < 10 {
        per_probe.push("000000".to_string());
        ext_digests.push("0".repeat(64));
    }

    let cipher_block: String = per_probe
        .iter()
        .flat_map(|s| s.chars())
        .take(30)
        .collect();

    let mut hasher = Sha256::new();
    hasher.update(ext_digests.join("|").as_bytes());
    let ext_hash = hasher.finalize();
    let mut ext_hex = String::with_capacity(64);
    for b in ext_hash.iter() {
        ext_hex.push_str(&format!("{b:02x}"));
    }

    format!("{}{}", cipher_block, &ext_hex[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_summaries_produce_stable_hash() {
        let h = jarm_hash(&[]);
        assert_eq!(h.len(), 62);
        let h2 = jarm_hash(&[]);
        assert_eq!(h, h2, "all-null hash must be deterministic");
    }

    #[test]
    fn non_empty_differs_from_empty() {
        let s = ServerHelloSummary {
            tls_version: Some(0x0303),
            cipher: Some(0xc02f),
            extension_digest: "a".repeat(64),
        };
        let populated = jarm_hash(&vec![s; 10]);
        let empty = jarm_hash(&[]);
        assert_ne!(populated, empty);
        assert_eq!(populated.len(), 62);
    }

    #[test]
    fn extension_codes_digest_is_stable() {
        let exts = &[
            0x00, 0x00, 0x00, 0x00, // ext 0 length 0
            0x00, 0x17, 0x00, 0x00, // ext 0x17 length 0
        ];
        let a = extension_codes_digest(exts);
        let b = extension_codes_digest(exts);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
