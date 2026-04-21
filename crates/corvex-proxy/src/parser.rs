//! Minimal HTTP/1.x request wire parser.
//!
//! Used only to validate user-edited intercepts and replay inputs
//! before they hit the upstream client — a malformed edit must not
//! silently go on the wire. corvex-core already has a raw response
//! parser; for requests we've never needed one because the scanner
//! builds requests programmatically. Keep the parser small and liberal
//! on purpose — clients already did their own validation.

use indexmap::IndexMap;

use corvex_core::http::request::Request;

/// Parse a raw HTTP/1.x request (as produced by `Request::to_wire`) into
/// a [`Request`]. The `fallback_host` / `fallback_port` / `fallback_ssl`
/// arguments are used when the request line uses origin-form (no
/// scheme/authority) and no `Host` header is present — they come from
/// the parent exchange so edits can't accidentally retarget the
/// request to a different origin without an explicit change.
pub fn parse_request(
    bytes: &[u8],
    fallback_host: &str,
    fallback_port: u16,
    fallback_ssl: bool,
) -> Result<Request, String> {
    let sep = find(bytes, b"\r\n\r\n").ok_or_else(|| "missing header terminator".to_string())?;
    let (head, body) = (&bytes[..sep], &bytes[sep + 4..]);
    let head_str = std::str::from_utf8(head).map_err(|e| format!("non-utf8 head: {e}"))?;
    let mut lines = head_str.split("\r\n");

    let request_line = lines.next().ok_or_else(|| "empty request".to_string())?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| "missing target".to_string())?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| "missing version".to_string())?
        .trim()
        .strip_prefix("HTTP/")
        .unwrap_or("1.1")
        .to_string();

    let mut headers = IndexMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed header: {line:?}"))?;
        headers.insert(k.trim().to_string(), v.trim().to_string());
    }

    // Decide host/port/ssl.
    let (host, port, ssl, uri) = resolve_target(
        &target,
        &headers,
        fallback_host,
        fallback_port,
        fallback_ssl,
    )?;

    Ok(Request {
        method,
        uri,
        version,
        host,
        port,
        ssl,
        headers,
        body: body.to_vec(),
        timeout_secs: 30,
    })
}

fn resolve_target(
    target: &str,
    headers: &IndexMap<String, String>,
    fallback_host: &str,
    fallback_port: u16,
    fallback_ssl: bool,
) -> Result<(String, u16, bool, String), String> {
    // Absolute-form: `http://host/path` or `https://host:port/path`.
    if let Some(rest) = target.strip_prefix("http://").or_else(|| target.strip_prefix("https://")) {
        let ssl = target.starts_with("https://");
        let default_port = if ssl { 443 } else { 80 };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = parse_authority(authority, default_port);
        return Ok((host, port, ssl, path.to_string()));
    }

    // Origin-form: path only. Derive host from Host header or fallback.
    let host_hdr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    if let Some(h) = host_hdr {
        let (host, port) = parse_authority(h, if fallback_ssl { 443 } else { 80 });
        return Ok((host, port, fallback_ssl, target.to_string()));
    }
    Ok((
        fallback_host.to_string(),
        fallback_port,
        fallback_ssl,
        target.to_string(),
    ))
}

fn parse_authority(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), default_port),
        },
        None => (authority.to_string(), default_port),
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_form_uses_host_header() {
        let wire = b"GET /api HTTP/1.1\r\nHost: example.com:8443\r\n\r\n";
        let r = parse_request(wire, "fallback", 80, false).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.uri, "/api");
        assert_eq!(r.host, "example.com");
        assert_eq!(r.port, 8443);
    }

    #[test]
    fn absolute_form_overrides_host() {
        let wire =
            b"POST https://api.example.com:9000/submit HTTP/1.1\r\nHost: ignored\r\n\r\nbody";
        let r = parse_request(wire, "fallback", 80, false).unwrap();
        assert!(r.ssl);
        assert_eq!(r.host, "api.example.com");
        assert_eq!(r.port, 9000);
        assert_eq!(r.uri, "/submit");
        assert_eq!(r.body, b"body");
    }

    #[test]
    fn rejects_missing_terminator() {
        assert!(parse_request(b"GET / HTTP/1.1\r\nHost: x\r\n", "x", 80, false).is_err());
    }
}
