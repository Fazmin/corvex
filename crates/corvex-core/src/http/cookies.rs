//! Minimal cookie jar. Mirrors LW2's looseness around path/domain matching.

use indexmap::IndexMap;

use super::request::Request;
use super::response::Response;

#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    /// name -> value. LW2 is path/domain-agnostic, so we are too.
    cookies: IndexMap<String, String>,
}

impl CookieJar {
    pub fn set(&mut self, name: &str, value: &str) {
        self.cookies.insert(name.to_string(), value.to_string());
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.cookies.get(name).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Read Set-Cookie headers from a response and store them.
    pub fn read_from(&mut self, resp: &Response) {
        for (k, v) in &resp.headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            // Cookie value is everything up to first ';'
            let pair = v.split(';').next().unwrap_or(v).trim();
            if let Some((name, val)) = pair.split_once('=') {
                self.cookies
                    .insert(name.trim().to_string(), val.trim().to_string());
            }
        }
    }

    /// Write all stored cookies into the request's Cookie header.
    pub fn write_into(&self, req: &mut Request) {
        if self.cookies.is_empty() {
            return;
        }
        let joined: Vec<String> = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        req.set_header("Cookie", &joined.join("; "));
    }
}
