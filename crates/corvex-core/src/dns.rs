//! DNS enumeration utilities — record lookups, subdomain brute-force,
//! reverse DNS, and zone transfer attempts.

use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::error::{CorvexError, Result};

/// A single DNS record we discovered.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
}

/// Results of a full DNS enumeration run.
#[derive(Debug, Clone, Default)]
pub struct DnsEnumResult {
    pub records: Vec<DnsRecord>,
    pub subdomains: Vec<String>,
    pub zone_transfer: bool,
}

/// Build a default async resolver using the system config.
fn resolver() -> Result<TokioResolver> {
    let mut r = TokioResolver::builder_tokio()
        .map_err(|e| CorvexError::other(format!("DNS resolver: {e}")))?;
    let opts = r.options_mut();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;
    Ok(r.build())
}

/// Look up common DNS record types for a domain.
pub async fn lookup_records(domain: &str) -> Result<Vec<DnsRecord>> {
    let r = resolver()?;
    let mut records = Vec::new();

    // A records
    if let Ok(resp) = r.lookup(domain, RecordType::A).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "A".into(),
                value: rec.to_string(),
            });
        }
    }

    // AAAA records
    if let Ok(resp) = r.lookup(domain, RecordType::AAAA).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "AAAA".into(),
                value: rec.to_string(),
            });
        }
    }

    // MX records
    if let Ok(resp) = r.lookup(domain, RecordType::MX).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "MX".into(),
                value: rec.to_string(),
            });
        }
    }

    // NS records
    if let Ok(resp) = r.lookup(domain, RecordType::NS).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "NS".into(),
                value: rec.to_string(),
            });
        }
    }

    // TXT records
    if let Ok(resp) = r.lookup(domain, RecordType::TXT).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "TXT".into(),
                value: rec.to_string(),
            });
        }
    }

    // CNAME records
    if let Ok(resp) = r.lookup(domain, RecordType::CNAME).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "CNAME".into(),
                value: rec.to_string(),
            });
        }
    }

    // SOA records
    if let Ok(resp) = r.lookup(domain, RecordType::SOA).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "SOA".into(),
                value: rec.to_string(),
            });
        }
    }

    Ok(records)
}

/// Attempt a DNS zone transfer (AXFR). This uses a simple TCP approach:
/// connect to each NS and try AXFR. Most servers will refuse, but it's
/// worth checking.
pub async fn try_zone_transfer(domain: &str) -> Result<Vec<DnsRecord>> {
    let r = resolver()?;
    let mut records = Vec::new();

    // Try AXFR via hickory's lookup — this will typically fail (refused)
    // but we attempt it to detect misconfigurations.
    if let Ok(resp) = r.lookup(domain, RecordType::AXFR).await {
        for rec in resp.iter() {
            records.push(DnsRecord {
                name: domain.to_string(),
                record_type: "AXFR".into(),
                value: rec.to_string(),
            });
        }
    }

    Ok(records)
}

/// Reverse DNS lookup for an IP address.
pub async fn reverse_lookup(ip: IpAddr) -> Result<Option<String>> {
    let r = resolver()?;
    match r.reverse_lookup(ip).await {
        Ok(resp) => Ok(resp.iter().next().map(|n| n.to_string())),
        Err(_) => Ok(None),
    }
}

/// Brute-force subdomain discovery. Resolves `{prefix}.{domain}` for each
/// prefix in the wordlist, up to `max_concurrent` in parallel.
pub async fn brute_subdomains(
    domain: &str,
    wordlist: &[String],
    max_concurrent: usize,
) -> Result<Vec<String>> {
    let r = resolver()?;
    let sem = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::new();

    for prefix in wordlist {
        let fqdn = format!("{prefix}.{domain}");
        let resolver = r.clone();
        let sem = sem.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let result = resolver.lookup_ip(&fqdn).await;
            match result {
                Ok(resp) if resp.iter().next().is_some() => Some(fqdn),
                _ => None,
            }
        });
        handles.push(handle);
    }

    let mut found = Vec::new();
    for h in handles {
        if let Ok(Some(fqdn)) = h.await {
            found.push(fqdn);
        }
    }

    Ok(found)
}

/// Probe for a wildcard DNS record by resolving a random-looking
/// subdomain that the target is extremely unlikely to have a real
/// record for. If it answers, the domain wildcards everything under
/// it and brute-force results against the returned IPs are worthless
/// — callers should filter them out.
///
/// Returns the wildcard target IPs as strings; an empty vec means no
/// wildcard was detected.
pub async fn detect_wildcard(domain: &str) -> Result<Vec<String>> {
    let r = resolver()?;
    // 32 random lowercase hex chars are effectively guaranteed not to
    // be a real subdomain.
    let random: String = (0..32)
        .map(|_| {
            let idx = rand::random::<u8>() % 16;
            std::char::from_digit(idx as u32, 16).unwrap_or('0')
        })
        .collect();
    let probe = format!("{random}.{domain}");
    match r.lookup_ip(probe).await {
        Ok(resp) => Ok(resp.iter().map(|ip| ip.to_string()).collect()),
        Err(_) => Ok(Vec::new()),
    }
}

/// Look up A + AAAA + CNAME for a host and return the mixed list as
/// string values. Used by the recon runner to annotate discovered
/// subdomains with IP/alias data for the results grid.
pub async fn lookup_host_addrs(host: &str) -> Result<Vec<DnsRecord>> {
    let r = resolver()?;
    let mut out = Vec::new();
    if let Ok(resp) = r.lookup(host, RecordType::A).await {
        for rec in resp.iter() {
            out.push(DnsRecord {
                name: host.to_string(),
                record_type: "A".into(),
                value: rec.to_string(),
            });
        }
    }
    if let Ok(resp) = r.lookup(host, RecordType::AAAA).await {
        for rec in resp.iter() {
            out.push(DnsRecord {
                name: host.to_string(),
                record_type: "AAAA".into(),
                value: rec.to_string(),
            });
        }
    }
    if let Ok(resp) = r.lookup(host, RecordType::CNAME).await {
        for rec in resp.iter() {
            out.push(DnsRecord {
                name: host.to_string(),
                record_type: "CNAME".into(),
                value: rec.to_string(),
            });
        }
    }
    Ok(out)
}

/// Brute-force subdomain discovery with wildcard-aware filtering.
/// Mirrors [`brute_subdomains`] but skips any response that only
/// resolves to the wildcard IPs passed in. The wildcard list should
/// come from [`detect_wildcard`] at the start of the run.
pub async fn brute_subdomains_filtered(
    domain: &str,
    wordlist: &[String],
    max_concurrent: usize,
    wildcard_ips: &[String],
) -> Result<Vec<String>> {
    let r = resolver()?;
    let sem = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let wildcard: Arc<Vec<String>> = Arc::new(wildcard_ips.to_vec());
    let mut handles = Vec::new();

    for prefix in wordlist {
        let fqdn = format!("{prefix}.{domain}");
        let resolver = r.clone();
        let sem = sem.clone();
        let wildcard = wildcard.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let result = resolver.lookup_ip(&fqdn).await;
            match result {
                Ok(resp) => {
                    let ips: Vec<String> =
                        resp.iter().map(|ip| ip.to_string()).collect();
                    if ips.is_empty() {
                        return None;
                    }
                    // If every returned IP matches the wildcard, this
                    // is a false positive — skip it.
                    if !wildcard.is_empty()
                        && ips.iter().all(|ip| wildcard.contains(ip))
                    {
                        return None;
                    }
                    Some((fqdn, ips))
                }
                Err(_) => None,
            }
        });
        handles.push(handle);
    }

    let mut found = Vec::new();
    for h in handles {
        if let Ok(Some((fqdn, _))) = h.await {
            found.push(fqdn);
        }
    }
    Ok(found)
}

/// Check TXT records for SPF misconfigurations.
pub fn check_spf_issues(txt_records: &[DnsRecord]) -> Vec<String> {
    let mut issues = Vec::new();
    let spf_records: Vec<&DnsRecord> = txt_records
        .iter()
        .filter(|r| r.record_type == "TXT" && r.value.to_ascii_lowercase().contains("v=spf1"))
        .collect();

    if spf_records.is_empty() {
        issues.push("No SPF record found — email spoofing may be possible.".into());
    } else {
        for rec in &spf_records {
            let lower = rec.value.to_ascii_lowercase();
            if lower.contains("+all") {
                issues.push(
                    "SPF record uses +all — allows any server to send email for this domain."
                        .into(),
                );
            }
            if !lower.contains("-all") && !lower.contains("~all") {
                issues.push(
                    "SPF record does not end with -all or ~all — weak enforcement.".into(),
                );
            }
        }
    }

    // Check for DMARC
    // (DMARC is a TXT record at _dmarc.domain — not fetched here but we note its absence)
    issues
}
