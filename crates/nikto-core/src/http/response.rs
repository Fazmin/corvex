//! An HTTP response, parsed from the wire.

use indexmap::IndexMap;

#[derive(Debug, Clone, Default)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub version: String,
    pub headers: IndexMap<String, String>,
    pub body: Vec<u8>,
    pub error: Option<String>,
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
        })
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
