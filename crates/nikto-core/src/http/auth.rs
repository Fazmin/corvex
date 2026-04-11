//! HTTP authentication helpers. Basic is complete; Digest/NTLM stubs for now.

use super::request::Request;
use base64::Engine;

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
