//! Asset identity helpers — collapse cosmetic variants of the same
//! host into one canonical key so cross-source joins work.
//!
//! Hostnames arrive from three places — recon (DNS-derived, may carry a
//! trailing dot), proxy exchanges (URL-parsed, mixed case in the wild),
//! and probe runs (user-typed, anything goes). Without normalization a
//! query for `Login.Acme.COM.` would miss findings recorded against
//! `login.acme.com`.
//!
//! This module is intentionally small: one normalizer + one helper to
//! pull the registrable suffix for "same root domain" relationships.

/// Canonical lower-case form with the trailing dot stripped. IPv6
/// brackets are removed too so `[::1]` and `::1` collide. Empty input
/// becomes empty output — callers should guard against that earlier.
pub fn normalize_host(s: &str) -> String {
    let trimmed = s.trim().trim_end_matches('.');
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed.to_ascii_lowercase()
}

/// Coarse "registrable suffix" — last two labels of a hostname, or the
/// whole thing when it's an IP literal or single-label name. This is a
/// deliberately simple stand-in for a real PSL lookup; it's accurate
/// enough for related-host clustering inside one engagement and avoids
/// pulling in the full `publicsuffix` crate for one screen.
pub fn registrable_suffix(host: &str) -> String {
    let h = normalize_host(host);
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    let labels: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if labels.len() <= 2 {
        return h;
    }
    let n = labels.len();
    format!("{}.{}", labels[n - 2], labels[n - 1])
}

/// `/24` network for an IPv4 literal — used by the related-assets
/// "same network" panel. Returns `None` for IPv6 (we don't surface
/// IPv6 neighborhoods today; `/64` would be most of the internet).
pub fn cidr_24(ip: &str) -> Option<String> {
    let v4: std::net::Ipv4Addr = ip.trim().parse().ok()?;
    let octets = v4.octets();
    Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(normalize_host("Login.Acme.COM."), "login.acme.com");
        assert_eq!(normalize_host("  EXAMPLE.com "), "example.com");
        assert_eq!(normalize_host("example.com"), "example.com");
    }

    #[test]
    fn unbrackets_ipv6() {
        assert_eq!(normalize_host("[::1]"), "::1");
        assert_eq!(normalize_host("::1"), "::1");
    }

    #[test]
    fn registrable_for_subdomains() {
        assert_eq!(registrable_suffix("api.example.com"), "example.com");
        assert_eq!(registrable_suffix("a.b.c.example.com"), "example.com");
        assert_eq!(registrable_suffix("example.com"), "example.com");
        assert_eq!(registrable_suffix("localhost"), "localhost");
    }

    #[test]
    fn registrable_passes_through_ip() {
        assert_eq!(registrable_suffix("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn cidr_24_extracts_block() {
        assert_eq!(cidr_24("93.184.216.34"), Some("93.184.216.0/24".into()));
        assert_eq!(cidr_24("not-an-ip"), None);
        assert_eq!(cidr_24("::1"), None);
    }
}
