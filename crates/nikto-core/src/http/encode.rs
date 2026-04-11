//! URI encoders + Nikto evasion transforms.
//!
//! Ports of the LW2 helpers `encode_uri_hex`, `encode_uri_randomhex`,
//! `encode_uri_randomcase`, `encode_unicode`, and the `-evasion` table.

use rand::Rng;

/// %XX hex encode every non-alnum byte.
pub fn encode_hex(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || *b == b'/' {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02x}", b));
        }
    }
    out
}

/// Randomly encode roughly half the bytes as %XX.
pub fn encode_random_hex(s: &str) -> String {
    let mut rng = rand::thread_rng();
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        if *b != b'/' && rng.gen_bool(0.5) {
            out.push_str(&format!("%{:02x}", b));
        } else {
            out.push(*b as char);
        }
    }
    out
}

/// Randomize ASCII letter case.
pub fn encode_random_case(s: &str) -> String {
    let mut rng = rand::thread_rng();
    s.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                if rng.gen_bool(0.5) {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            } else {
                c
            }
        })
        .collect()
}

/// %uXXXX unicode encoding used by some IIS-era evasion tricks.
pub fn encode_unicode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 6);
    for c in s.chars() {
        if c == '/' {
            out.push('/');
        } else {
            out.push_str(&format!("%u{:04x}", c as u32));
        }
    }
    out
}
