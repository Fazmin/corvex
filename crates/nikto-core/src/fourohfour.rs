//! 404 detection heuristic.
//!
//! Strategy (matches Perl `is_404`):
//!   1. If user supplied `-404string` or `-404code`, those win.
//!   2. Status code 404/410 → not-found.
//!   3. Body matches any signature in db_404_strings → not-found.
//!   4. Body length / MD5 equals the cached baseline of a known
//!      non-existent path → not-found.

use md5::{Digest, Md5};

use crate::db::Databases;
use crate::http::response::Response;

#[derive(Debug, Default, Clone)]
pub struct FourOhFourCache {
    pub baseline_md5: Option<String>,
    pub baseline_len: Option<usize>,
    pub user_string: Option<String>,
    pub user_code: Option<u16>,
}

impl FourOhFourCache {
    pub fn seed_baseline(&mut self, resp: &Response) {
        self.baseline_md5 = Some(body_md5(&resp.body));
        self.baseline_len = Some(resp.body.len());
    }

    pub fn is_404(&self, resp: &Response, dbs: &Databases) -> bool {
        if let Some(code) = self.user_code {
            if resp.status == code {
                return true;
            }
        }
        if let Some(s) = &self.user_string {
            if resp.body_str().contains(s.as_str()) {
                return true;
            }
        }
        if matches!(resp.status, 404 | 410) {
            return true;
        }
        let body = resp.body_str();
        for sig in &dbs.fourohfour.signatures {
            if body.contains(sig.as_str()) {
                return true;
            }
        }
        if let (Some(ref hash), Some(len)) = (&self.baseline_md5, self.baseline_len) {
            if resp.body.len() == len && &body_md5(&resp.body) == hash {
                return true;
            }
        }
        false
    }
}

fn body_md5(body: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(body);
    hex::encode_upper(h.finalize())
}

// Tiny inline hex helper to avoid pulling in the `hex` crate.
mod hex {
    pub fn encode_upper<T: AsRef<[u8]>>(b: T) -> String {
        const HEX: &[u8] = b"0123456789ABCDEF";
        let b = b.as_ref();
        let mut out = String::with_capacity(b.len() * 2);
        for byte in b {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
