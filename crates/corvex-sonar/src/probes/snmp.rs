//! Minimal SNMPv2c probe.
//!
//! Sends one UDP/161 GET asking for `sysDescr.0` and `sysObjectID.0`,
//! waits up to a caller-supplied timeout, and returns whichever values
//! the agent answered with. Designed as a side-channel to the regular
//! TCP probe pipeline — it does not implement the `Probe` trait
//! because that trait assumes a TCP connector.
//!
//! The BER encoding is hand-rolled to avoid pulling a third-party SNMP
//! crate into the workspace. Only the subset needed for these two
//! OIDs is implemented; anything more elaborate (walks, sets, v3
//! authentication) is intentionally out of scope.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Clone, Default)]
pub struct SnmpProbeResult {
    pub sys_descr: Option<String>,
    pub sys_object_id: Option<String>,
    /// Which community string actually succeeded (handy for the UI).
    pub community: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnmpProbeOpts {
    /// Communities tried in order; first one that yields a non-empty
    /// response wins.
    pub communities: Vec<String>,
    /// Per-attempt timeout. The total budget is roughly
    /// `communities.len() * timeout`.
    pub timeout: Duration,
}

impl Default for SnmpProbeOpts {
    fn default() -> Self {
        Self {
            communities: vec!["public".to_string()],
            timeout: Duration::from_millis(1500),
        }
    }
}

/// Run the probe against `target` (typically `<ip>:161`). Returns
/// `Ok(None)` when no community produced a usable response.
pub async fn probe(
    target: SocketAddr,
    opts: &SnmpProbeOpts,
) -> std::io::Result<Option<SnmpProbeResult>> {
    let bind: SocketAddr = match target {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    for (i, community) in opts.communities.iter().enumerate() {
        let request_id = (std::process::id() as i32).wrapping_add(i as i32);
        let pdu = encode_get_request(community.as_bytes(), request_id);
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(target).await?;
        if sock.send(&pdu).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        let n = match timeout(opts.timeout, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            _ => continue,
        };
        buf.truncate(n);
        match decode_get_response(&buf, request_id) {
            Some(parsed) => {
                if parsed.sys_descr.is_some() || parsed.sys_object_id.is_some() {
                    return Ok(Some(SnmpProbeResult {
                        sys_descr: parsed.sys_descr,
                        sys_object_id: parsed.sys_object_id,
                        community: Some(community.clone()),
                    }));
                }
            }
            None => continue,
        }
    }
    Ok(None)
}

// ============================================================================
// BER encoder — only what we need for the GET PDU.
// ============================================================================

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_GET_REQUEST: u8 = 0xa0;
const TAG_GET_RESPONSE: u8 = 0xa2;

/// `1.3.6.1.2.1.1.1.0` — sysDescr
const OID_SYS_DESCR_BER: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
/// `1.3.6.1.2.1.1.2.0` — sysObjectID
const OID_SYS_OBJECT_ID_BER: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00];

fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else {
        // Larger lengths aren't expected for our payloads; encode 3
        // bytes anyway to keep the function total.
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xff) as u8,
        ]
    }
}

fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(tag);
    out.extend(encode_length(body.len()));
    out.extend(body);
    out
}

fn encode_integer(v: i32) -> Vec<u8> {
    // Two's-complement, minimum bytes.
    let bytes = v.to_be_bytes();
    let mut start = 0;
    if v >= 0 {
        while start < 3 && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
            start += 1;
        }
    } else {
        while start < 3 && bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }
    wrap(TAG_INTEGER, &bytes[start..])
}

fn encode_get_request(community: &[u8], request_id: i32) -> Vec<u8> {
    let oid_descr = wrap(TAG_OID, OID_SYS_DESCR_BER);
    let oid_id = wrap(TAG_OID, OID_SYS_OBJECT_ID_BER);
    let null = vec![TAG_NULL, 0x00];

    let mut vb1 = Vec::new();
    vb1.extend(&oid_descr);
    vb1.extend(&null);
    let varbind1 = wrap(TAG_SEQUENCE, &vb1);

    let mut vb2 = Vec::new();
    vb2.extend(&oid_id);
    vb2.extend(&null);
    let varbind2 = wrap(TAG_SEQUENCE, &vb2);

    let mut vb_body = Vec::new();
    vb_body.extend(&varbind1);
    vb_body.extend(&varbind2);
    let varbind_list = wrap(TAG_SEQUENCE, &vb_body);

    let req_id = encode_integer(request_id);
    let zero = encode_integer(0);

    let mut pdu_body = Vec::new();
    pdu_body.extend(&req_id);
    pdu_body.extend(&zero);
    pdu_body.extend(&zero);
    pdu_body.extend(&varbind_list);
    let pdu = wrap(TAG_GET_REQUEST, &pdu_body);

    let version = encode_integer(1); // SNMPv2c is version field 1
    let community = wrap(TAG_OCTET_STRING, community);

    let mut body = Vec::new();
    body.extend(&version);
    body.extend(&community);
    body.extend(&pdu);
    wrap(TAG_SEQUENCE, &body)
}

// ============================================================================
// BER decoder — minimal walker over the GetResponse PDU.
// ============================================================================

#[derive(Debug, Default)]
struct ParsedResponse {
    sys_descr: Option<String>,
    sys_object_id: Option<String>,
}

fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if buf.is_empty() {
        return None;
    }
    let tag = buf[0];
    if buf.len() < 2 {
        return None;
    }
    let first_len = buf[1];
    let (len, header) = if first_len & 0x80 == 0 {
        (first_len as usize, 2usize)
    } else {
        let n = (first_len & 0x7f) as usize;
        if n == 0 || buf.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | buf[2 + i] as usize;
        }
        (len, 2 + n)
    };
    if buf.len() < header + len {
        return None;
    }
    let body = &buf[header..header + len];
    let rest = &buf[header + len..];
    Some((tag, body, rest))
}

fn skip_tlv(buf: &[u8]) -> Option<&[u8]> {
    let (_, _, rest) = read_tlv(buf)?;
    Some(rest)
}

fn decode_oid(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let mut out = String::new();
    let first = body[0];
    let a = (first / 40) as u32;
    let b = (first % 40) as u32;
    out.push_str(&a.to_string());
    out.push('.');
    out.push_str(&b.to_string());

    let mut i = 1;
    while i < body.len() {
        let mut subid: u64 = 0;
        loop {
            if i >= body.len() {
                return None;
            }
            let byte = body[i];
            i += 1;
            subid = (subid << 7) | (byte & 0x7f) as u64;
            if byte & 0x80 == 0 {
                break;
            }
            if subid > (u32::MAX as u64) {
                return None;
            }
        }
        out.push('.');
        out.push_str(&subid.to_string());
    }
    Some(out)
}

fn decode_get_response(buf: &[u8], expected_request_id: i32) -> Option<ParsedResponse> {
    let (tag, body, _rest) = read_tlv(buf)?;
    if tag != TAG_SEQUENCE {
        return None;
    }
    // version
    let body = skip_tlv(body)?;
    // community
    let body = skip_tlv(body)?;
    // GetResponse-PDU
    let (pdu_tag, pdu_body, _) = read_tlv(body)?;
    if pdu_tag != TAG_GET_RESPONSE {
        return None;
    }
    // request-id
    let (rid_tag, rid_body, after_rid) = read_tlv(pdu_body)?;
    if rid_tag != TAG_INTEGER {
        return None;
    }
    let rid = decode_integer(rid_body)?;
    if rid != expected_request_id {
        // Stale / mismatched response — refuse to merge it into our
        // results lest we associate values with the wrong request.
        return None;
    }
    // error-status
    let after_es = skip_tlv(after_rid)?;
    // error-index
    let after_ei = skip_tlv(after_es)?;
    // varbind-list
    let (vbl_tag, vbl_body, _) = read_tlv(after_ei)?;
    if vbl_tag != TAG_SEQUENCE {
        return None;
    }

    let mut out = ParsedResponse::default();
    let mut cursor = vbl_body;
    while !cursor.is_empty() {
        let (vb_tag, vb_body, rest) = read_tlv(cursor)?;
        cursor = rest;
        if vb_tag != TAG_SEQUENCE {
            continue;
        }
        let (oid_tag, oid_body, after_oid) = read_tlv(vb_body)?;
        if oid_tag != TAG_OID {
            continue;
        }
        let (val_tag, val_body, _) = read_tlv(after_oid)?;
        // Match against the two OIDs we asked for.
        if oid_body == OID_SYS_DESCR_BER && val_tag == TAG_OCTET_STRING {
            if let Ok(s) = std::str::from_utf8(val_body) {
                out.sys_descr = Some(s.trim().to_string());
            } else {
                out.sys_descr = Some(String::from_utf8_lossy(val_body).trim().to_string());
            }
        } else if oid_body == OID_SYS_OBJECT_ID_BER && val_tag == TAG_OID {
            if let Some(dot) = decode_oid(val_body) {
                out.sys_object_id = Some(dot);
            }
        }
    }
    Some(out)
}

fn decode_integer(body: &[u8]) -> Option<i32> {
    if body.is_empty() || body.len() > 4 {
        return None;
    }
    let mut v: i32 = if body[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in body {
        v = (v << 8) | (b as i32 & 0xff);
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request() -> Vec<u8> {
        encode_get_request(b"public", 0x1234_5678)
    }

    #[test]
    fn request_starts_with_sequence() {
        let r = round_trip_request();
        assert_eq!(r[0], TAG_SEQUENCE);
        assert!(r.len() > 30);
    }

    #[test]
    fn decode_synthetic_response() {
        // Build a fake GetResponse with both var-bindings populated.
        let descr_value = b"Test device description";
        let oid_value: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x09, 0x01, 0x84, 0x04];

        let oid_descr = wrap(TAG_OID, OID_SYS_DESCR_BER);
        let val_descr = wrap(TAG_OCTET_STRING, descr_value);
        let mut vb1 = Vec::new();
        vb1.extend(&oid_descr);
        vb1.extend(&val_descr);
        let vb1 = wrap(TAG_SEQUENCE, &vb1);

        let oid_id = wrap(TAG_OID, OID_SYS_OBJECT_ID_BER);
        let val_id = wrap(TAG_OID, oid_value);
        let mut vb2 = Vec::new();
        vb2.extend(&oid_id);
        vb2.extend(&val_id);
        let vb2 = wrap(TAG_SEQUENCE, &vb2);

        let mut vbl = Vec::new();
        vbl.extend(&vb1);
        vbl.extend(&vb2);
        let vbl = wrap(TAG_SEQUENCE, &vbl);

        let req_id = encode_integer(42);
        let zero = encode_integer(0);
        let mut pdu = Vec::new();
        pdu.extend(&req_id);
        pdu.extend(&zero);
        pdu.extend(&zero);
        pdu.extend(&vbl);
        let pdu = wrap(TAG_GET_RESPONSE, &pdu);

        let version = encode_integer(1);
        let community = wrap(TAG_OCTET_STRING, b"public");
        let mut body = Vec::new();
        body.extend(&version);
        body.extend(&community);
        body.extend(&pdu);
        let frame = wrap(TAG_SEQUENCE, &body);

        let parsed = decode_get_response(&frame, 42).expect("parse");
        assert_eq!(parsed.sys_descr.as_deref(), Some("Test device description"));
        // 0x84 0x04 → (4*128 + 4) = 516 — Cisco IOS subid encoding.
        assert_eq!(
            parsed.sys_object_id.as_deref(),
            Some("1.3.6.1.4.1.9.1.516")
        );
    }

    #[test]
    fn rejects_mismatched_request_id() {
        // Reuse the synthetic frame with rid=42 but ask for rid=999.
        let descr_value = b"X";
        let oid_descr = wrap(TAG_OID, OID_SYS_DESCR_BER);
        let val_descr = wrap(TAG_OCTET_STRING, descr_value);
        let mut vb1 = Vec::new();
        vb1.extend(&oid_descr);
        vb1.extend(&val_descr);
        let vb1 = wrap(TAG_SEQUENCE, &vb1);
        let vbl = wrap(TAG_SEQUENCE, &vb1);

        let req_id = encode_integer(42);
        let zero = encode_integer(0);
        let mut pdu = Vec::new();
        pdu.extend(&req_id);
        pdu.extend(&zero);
        pdu.extend(&zero);
        pdu.extend(&vbl);
        let pdu = wrap(TAG_GET_RESPONSE, &pdu);

        let version = encode_integer(1);
        let community = wrap(TAG_OCTET_STRING, b"public");
        let mut body = Vec::new();
        body.extend(&version);
        body.extend(&community);
        body.extend(&pdu);
        let frame = wrap(TAG_SEQUENCE, &body);

        assert!(decode_get_response(&frame, 999).is_none());
    }
}
