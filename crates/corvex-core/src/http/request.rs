//! A raw HTTP/1.x request — matches LW2's `whisker` structure.

use indexmap::IndexMap;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub version: String,        // "1.0" | "1.1"
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub headers: IndexMap<String, String>,
    pub body: Vec<u8>,
    pub timeout_secs: u64,
}

impl Request {
    pub fn new(host: &str, port: u16, method: &str, uri: &str) -> Self {
        let mut headers = IndexMap::new();
        headers.insert("Host".to_string(), host.to_string());
        headers.insert(
            "User-Agent".to_string(),
            format!("Mozilla/5.00 (Corvex/{})", crate::VERSION),
        );
        headers.insert("Connection".to_string(), "close".to_string());
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            version: "1.1".to_string(),
            host: host.to_string(),
            port,
            ssl: false,
            headers,
            body: Vec::new(),
            timeout_secs: 15,
        }
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_string(), value.to_string());
    }

    /// Serialize into raw HTTP/1.x wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(
            format!("{} {} HTTP/{}\r\n", self.method, self.uri, self.version).as_bytes(),
        );
        let mut has_host = false;
        let mut has_cl = false;
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            if k.eq_ignore_ascii_case("content-length") {
                has_cl = true;
            }
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        if !has_host {
            out.extend_from_slice(format!("Host: {}\r\n", self.host).as_bytes());
        }
        if !has_cl && !self.body.is_empty() {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}
