//! OS ARP / neighbour cache lookup.
//!
//! Resolves an `IpAddr` to its MAC address by reading whatever the
//! kernel already has cached. We deliberately do **not** issue raw ARP
//! requests — that would require privileged sockets and is out of
//! scope for an unprivileged Tauri build. We rely on the fact that
//! any preceding TCP / UDP traffic to an L2-adjacent host populates
//! the cache, so a corvex probe pass that just exchanged SYNs leaves
//! the entry already in place by the time this function runs.
//!
//! Limitations (documented in the Datasets tab):
//!   * Only L2-adjacent hosts return a useful MAC. For routed targets
//!     the cache holds the **upstream router's** MAC, not the target's.
//!   * Linux kernels with strict netlink ACLs or some Windows EDR /
//!     AV products may return empty output. The caller treats `None`
//!     as "no info available" and proceeds normally.

use std::net::IpAddr;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

/// Look up a MAC address from the OS ARP / neighbour cache.
/// Returns `None` if the cache is empty for `ip`, the OS command
/// fails, or the timeout elapses.
pub async fn arp_lookup(ip: IpAddr) -> Option<String> {
    let ip_str = ip.to_string();
    let attempt_timeout = Duration::from_millis(800);

    let stdout = if cfg!(target_os = "windows") {
        run_capture(timeout(attempt_timeout, Command::new("arp").args(["-a", &ip_str]).output()).await).await
    } else if cfg!(target_os = "linux") {
        // `ip neigh show <ip>` is the canonical modern source. Fall
        // back to `arp -n` for distros without iproute2 in PATH.
        let primary = run_capture(
            timeout(
                attempt_timeout,
                Command::new("ip").args(["neigh", "show", &ip_str]).output(),
            )
            .await,
        )
        .await;
        match &primary {
            Some(s) if has_mac(s) => primary,
            _ => run_capture(
                timeout(
                    attempt_timeout,
                    Command::new("arp").args(["-n", &ip_str]).output(),
                )
                .await,
            )
            .await,
        }
    } else {
        // macOS / BSDs: `arp -n` formats are similar to Windows.
        run_capture(timeout(attempt_timeout, Command::new("arp").args(["-n", &ip_str]).output()).await).await
    };

    stdout.as_deref().and_then(parse_mac)
}

async fn run_capture(
    res: Result<Result<std::process::Output, std::io::Error>, tokio::time::error::Elapsed>,
) -> Option<String> {
    match res {
        Ok(Ok(out)) if out.status.success() => {
            Some(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        _ => None,
    }
}

fn has_mac(s: &str) -> bool {
    parse_mac(s).is_some()
}

/// Pull the first plausible MAC out of free-form `arp` / `ip neigh`
/// output. Accepts colon- or dash-separated 6-octet hex. Returns the
/// MAC normalised to lower-case colon-separated form.
fn parse_mac(s: &str) -> Option<String> {
    // Walk byte-by-byte for a 17-char window matching the canonical
    // shape `xx:xx:xx:xx:xx:xx` (or with dashes). Avoids pulling in
    // an extra regex dependency for this single grammar.
    let bytes = s.as_bytes();
    if bytes.len() < 17 {
        return None;
    }
    'outer: for i in 0..=bytes.len() - 17 {
        let window = &bytes[i..i + 17];
        for (j, &b) in window.iter().enumerate() {
            if matches!(j, 2 | 5 | 8 | 11 | 14) {
                if b != b':' && b != b'-' {
                    continue 'outer;
                }
            } else if !b.is_ascii_hexdigit() {
                continue 'outer;
            }
        }
        let mut out = String::with_capacity(17);
        for (j, &b) in window.iter().enumerate() {
            if matches!(j, 2 | 5 | 8 | 11 | 14) {
                out.push(':');
            } else {
                out.push(b.to_ascii_lowercase() as char);
            }
        }
        // Reject obvious non-MACs that arp commands produce as
        // placeholders for "unresolved": ff-ff-ff-ff-ff-ff broadcast
        // is reserved; 00-00-00-00-00-00 means "no entry" on Windows.
        if out == "ff:ff:ff:ff:ff:ff" || out == "00:00:00:00:00:00" {
            return None;
        }
        return Some(out);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_arp_a_output() {
        let sample = "Interface: 192.168.1.5 --- 0xa\n  \
                      Internet Address      Physical Address      Type\n  \
                      192.168.1.1           00-11-22-aa-bb-cc     dynamic\n";
        assert_eq!(parse_mac(sample).as_deref(), Some("00:11:22:aa:bb:cc"));
    }

    #[test]
    fn parses_ip_neigh_output() {
        let sample = "192.168.1.1 dev eth0 lladdr 00:de:ad:be:ef:01 REACHABLE\n";
        assert_eq!(parse_mac(sample).as_deref(), Some("00:de:ad:be:ef:01"));
    }

    #[test]
    fn rejects_broadcast_and_zero() {
        assert!(parse_mac("ff:ff:ff:ff:ff:ff").is_none());
        assert!(parse_mac("00-00-00-00-00-00").is_none());
    }

    #[test]
    fn returns_none_when_no_mac_present() {
        assert!(parse_mac("no entry for that IP").is_none());
        assert!(parse_mac("").is_none());
    }
}
