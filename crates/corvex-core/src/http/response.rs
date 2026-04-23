//! An HTTP response, parsed from the wire.

use std::time::Duration;

use indexmap::IndexMap;

use crate::http::tls::SslInfo;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub version: String,
    pub headers: IndexMap<String, String>,
    pub body: Vec<u8>,
    pub error: Option<String>,
    /// TLS information for HTTPS responses; None for plaintext requests.
    pub tls: Option<SslInfo>,
    /// Wall-clock time from first byte sent to last byte received.
    pub elapsed: Duration,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status: 0,
            status_text: String::new(),
            version: String::new(),
            headers: IndexMap::new(),
            body: Vec::new(),
            error: None,
            tls: None,
            elapsed: Duration::ZERO,
        }
    }
}

impl Response {
    /// Parse a raw wire response (as we read it from the socket).
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        // Find header/body split
        let sep = find_subslice(buf, b"\r\n\r\n");
        let (head, body) = match sep {
            Some(idx) => (&buf[..idx], &buf[idx + 4..]),
            None => (buf, &[][..]),
        };
        let head_str = std::str::from_utf8(head)
            .map_err(|e| format!("non-utf8 header: {e}"))?;
        let mut lines = head_str.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| "empty response".to_string())?;
        let (version, status, status_text) = parse_status_line(status_line)?;

        let mut headers = IndexMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_string(), v.trim().to_string());
            }
        }

        Ok(Response {
            status,
            status_text,
            version,
            headers,
            body: body.to_vec(),
            error: None,
            tls: None,
            elapsed: Duration::ZERO,
        })
    }

    /// Serialise the response back into raw HTTP/1.x wire bytes. Used by
    /// the proxy to hand responses to the UI for in-flight editing —
    /// parse() composed with to_wire() is an identity modulo whitespace
    /// and header casing.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.body.len());
        let version = if self.version.is_empty() {
            "1.1"
        } else {
            self.version.as_str()
        };
        let reason = if self.status_text.is_empty() {
            default_reason(self.status)
        } else {
            self.status_text.as_str()
        };
        out.extend_from_slice(
            format!("HTTP/{} {} {}\r\n", version, self.status, reason).as_bytes(),
        );
        let mut has_cl = false;
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case("content-length") {
                has_cl = true;
            }
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        if !has_cl {
            out.extend_from_slice(
                format!("Content-Length: {}\r\n", self.body.len()).as_bytes(),
            );
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

fn parse_status_line(line: &str) -> Result<(String, u16, String), String> {
    // HTTP/1.1 200 OK
    let mut parts = line.splitn(3, ' ');
    let v = parts.next().unwrap_or("HTTP/1.0");
    let code = parts.next().unwrap_or("0");
    let rest = parts.next().unwrap_or("").to_string();
    let version = v.strip_prefix("HTTP/").unwrap_or("1.0").to_string();
    let status: u16 = code.parse().map_err(|e| format!("status: {e}"))?;
    Ok((version, status, rest))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn default_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        418 => "I'm a teapot",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}
