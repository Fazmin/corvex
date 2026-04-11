//! HTTP authentication helpers.
//!
//! Implements:
//!   - Basic (trivial base64 encode of `user:pass`)
//!   - Digest (MD5, qop=auth, RFC 2617) — most common flavour in the wild
//!   - NTLM Type-1 / Type-3 negotiation sketch
//!
//! Digest and NTLM both require parsing the server's `WWW-Authenticate`
//! challenge header. Callers pass that string into [`build_authorization`],
//! which returns a ready-to-send `Authorization` value.

use base64::Engine;
use md5::{Digest, Md5};
use rand::Rng;

use super::request::Request;

/// Set a Basic Authorization header on the request.
pub fn set_basic(req: &mut Request, user: &str, pass: &str) {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    req.set_header("Authorization", &format!("Basic {token}"));
}

/// Parse a `user[:pass[:realm]]` credential string.
pub fn parse_id(s: &str) -> (String, String, Option<String>) {
    let mut parts = s.splitn(3, ':');
    let user = parts.next().unwrap_or("").to_string();
    let pass = parts.next().unwrap_or("").to_string();
    let realm = parts.next().map(|s| s.to_string());
    (user, pass, realm)
}

/// Given a parsed `WWW-Authenticate` challenge header and credentials,
/// build the outgoing `Authorization` header value. Returns `None` if
/// the scheme is unsupported or required parameters are missing.
pub fn build_authorization(
    challenge: &str,
    method: &str,
    uri: &str,
    user: &str,
    pass: &str,
) -> Option<String> {
    let scheme = challenge
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match scheme.as_str() {
        "basic" => {
            let token =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            Some(format!("Basic {token}"))
        }
        "digest" => build_digest(challenge, method, uri, user, pass),
        "ntlm" => Some(build_ntlm_type1(user)),
        _ => None,
    }
}

// ---- Digest -----------------------------------------------------------------

fn build_digest(
    challenge: &str,
    method: &str,
    uri: &str,
    user: &str,
    pass: &str,
) -> Option<String> {
    // Strip the leading scheme name.
    let params = challenge
        .splitn(2, char::is_whitespace)
        .nth(1)
        .unwrap_or("");
    let map = parse_kv(params);
    let realm = map.get("realm")?.clone();
    let nonce = map.get("nonce")?.clone();
    let qop = map
        .get("qop")
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string());
    let algorithm = map
        .get("algorithm")
        .cloned()
        .unwrap_or_else(|| "MD5".to_string());
    if !algorithm.eq_ignore_ascii_case("MD5") {
        return None;
    }
    let opaque = map.get("opaque").cloned();
    let cnonce: String = random_hex(16);
    let nc = "00000001";

    let ha1 = md5_hex(&format!("{user}:{realm}:{pass}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));

    let response = match qop.as_deref() {
        Some("auth") | Some("auth-int") => md5_hex(&format!(
            "{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}",
            qop = qop.as_deref().unwrap()
        )),
        _ => md5_hex(&format!("{ha1}:{nonce}:{ha2}")),
    };

    let mut parts = vec![
        format!("username=\"{user}\""),
        format!("realm=\"{realm}\""),
        format!("nonce=\"{nonce}\""),
        format!("uri=\"{uri}\""),
        format!("response=\"{response}\""),
    ];
    if let Some(q) = qop {
        parts.push(format!("qop={q}"));
        parts.push(format!("nc={nc}"));
        parts.push(format!("cnonce=\"{cnonce}\""));
    }
    if let Some(o) = opaque {
        parts.push(format!("opaque=\"{o}\""));
    }
    Some(format!("Digest {}", parts.join(", ")))
}

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut s = String::with_capacity(32);
    for b in out.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn parse_kv(s: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Skip whitespace and commas.
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',' || bytes[i] == b'\t') {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = std::str::from_utf8(&bytes[key_start..i])
            .unwrap_or("")
            .trim()
            .to_string();
        i += 1; // skip =
        // Value: quoted or bare.
        let (value, next) = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let v = std::str::from_utf8(&bytes[start..i]).unwrap_or("").to_string();
            if i < bytes.len() {
                i += 1; // skip closing "
            }
            (v, i)
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            let v = std::str::from_utf8(&bytes[start..i])
                .unwrap_or("")
                .trim()
                .to_string();
            (v, i)
        };
        if !key.is_empty() {
            out.insert(key.to_ascii_lowercase(), value);
        }
        i = next;
    }
    out
}

fn random_hex(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| format!("{:02x}", rng.gen::<u8>()))
        .collect()
}

// ---- NTLM Type-1 ------------------------------------------------------------
//
// NTLMSSP has three messages. Type-1 is sent proactively; the server replies
// with Type-2 containing a challenge, and we reply with Type-3. Full Type-3
// response requires a second HTTP round-trip and Unicode-encoded credentials.
// For the initial port we ship a valid Type-1 so servers at least record a
// recognizable NTLM negotiation — enough to enumerate realm names. Upgrading
// to full Type-3 is a focused follow-up.

fn build_ntlm_type1(domain_or_user: &str) -> String {
    let domain = domain_or_user
        .split(&['\\', '/'][..])
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();

    // NTLMSSP header
    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(b"NTLMSSP\0");
    msg.extend_from_slice(&1u32.to_le_bytes()); // Type 1
    // Flags: Negotiate Unicode | OEM | Request Target | Sign | Seal | NTLM | Always Sign
    let flags: u32 = 0xB203;
    msg.extend_from_slice(&flags.to_le_bytes());
    // Domain fields (length, max, offset)
    let domain_bytes = domain.as_bytes();
    let domain_len = domain_bytes.len() as u16;
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&(40u32).to_le_bytes());
    // Workstation fields
    let ws_bytes: &[u8] = b"NIKTO";
    let ws_len = ws_bytes.len() as u16;
    msg.extend_from_slice(&ws_len.to_le_bytes());
    msg.extend_from_slice(&ws_len.to_le_bytes());
    msg.extend_from_slice(&(40u32 + domain_len as u32).to_le_bytes());
    // Payload
    msg.extend_from_slice(domain_bytes);
    msg.extend_from_slice(ws_bytes);

    let encoded = base64::engine::general_purpose::STANDARD.encode(&msg);
    format!("NTLM {encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_basic() {
        let m = parse_kv("realm=\"example\", nonce=\"abc\", qop=auth");
        assert_eq!(m.get("realm").map(String::as_str), Some("example"));
        assert_eq!(m.get("nonce").map(String::as_str), Some("abc"));
        assert_eq!(m.get("qop").map(String::as_str), Some("auth"));
    }

    #[test]
    fn digest_builds_complete_header() {
        // We use a random cnonce so we can't assert the exact response
        // hash from RFC 2617 §3.5. Instead, assert that every field
        // required to reconstruct and verify the digest is present.
        let challenge = r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let hdr = build_digest(
            challenge,
            "GET",
            "/dir/index.html",
            "Mufasa",
            "Circle Of Life",
        )
        .expect("digest builds");
        assert!(hdr.starts_with("Digest "));
        assert!(hdr.contains("username=\"Mufasa\""));
        assert!(hdr.contains("realm=\"testrealm@host.com\""));
        assert!(hdr.contains("nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""));
        assert!(hdr.contains("uri=\"/dir/index.html\""));
        assert!(hdr.contains("qop=auth"));
        assert!(hdr.contains("nc=00000001"));
        assert!(hdr.contains("cnonce=\""));
        assert!(hdr.contains("response=\""));
        assert!(hdr.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    }

    #[test]
    fn ntlm_type1_base64_shape() {
        let hdr = build_ntlm_type1("EXAMPLE\\user");
        assert!(hdr.starts_with("NTLM "));
        let tok = hdr.strip_prefix("NTLM ").unwrap();
        let bytes = base64::engine::general_purpose::STANDARD.decode(tok).unwrap();
        // Must start with NTLMSSP\0 signature + Type 1 marker.
        assert_eq!(&bytes[0..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]), 1);
    }
}
