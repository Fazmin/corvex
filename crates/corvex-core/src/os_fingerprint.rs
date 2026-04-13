//! OS fingerprinting via HTTP server banner analysis, service banner
//! cross-correlation, and port-based heuristics.

/// An OS guess with a confidence percentage.
#[derive(Debug, Clone)]
pub struct OsGuess {
    pub os_family: String,
    pub os_version: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

/// Fingerprint the OS from available banners and open port data.
pub fn fingerprint(
    http_banner: Option<&str>,
    ssh_banner: Option<&str>,
    open_ports: &[u16],
) -> Option<OsGuess> {
    let mut votes: Vec<(&str, Option<&str>, u8, String)> = Vec::new();

    // HTTP server header analysis
    if let Some(banner) = http_banner {
        let lower = banner.to_ascii_lowercase();

        if lower.contains("ubuntu") {
            votes.push(("Linux", Some("Ubuntu"), 60, format!("HTTP banner: {banner}")));
        } else if lower.contains("debian") {
            votes.push(("Linux", Some("Debian"), 60, format!("HTTP banner: {banner}")));
        } else if lower.contains("centos") || lower.contains("el7") || lower.contains("el8") {
            votes.push(("Linux", Some("CentOS/RHEL"), 55, format!("HTTP banner: {banner}")));
        } else if lower.contains("fedora") {
            votes.push(("Linux", Some("Fedora"), 55, format!("HTTP banner: {banner}")));
        } else if lower.contains("unix") || lower.contains("linux") {
            votes.push(("Linux", None, 40, format!("HTTP banner: {banner}")));
        } else if lower.contains("win32") || lower.contains("win64") || lower.contains("microsoft") || lower.contains("iis") {
            votes.push(("Windows", None, 55, format!("HTTP banner: {banner}")));
        } else if lower.contains("freebsd") {
            votes.push(("FreeBSD", None, 55, format!("HTTP banner: {banner}")));
        } else if lower.contains("openbsd") {
            votes.push(("OpenBSD", None, 55, format!("HTTP banner: {banner}")));
        } else if lower.contains("nginx") {
            // nginx is common on Linux but also runs elsewhere
            votes.push(("Linux", None, 25, format!("nginx (commonly Linux): {banner}")));
        } else if lower.contains("apache") {
            votes.push(("Linux", None, 30, format!("Apache (commonly Linux): {banner}")));
        }
    }

    // SSH banner analysis
    if let Some(banner) = ssh_banner {
        let lower = banner.to_ascii_lowercase();
        if lower.contains("ubuntu") {
            votes.push(("Linux", Some("Ubuntu"), 70, format!("SSH banner: {banner}")));
        } else if lower.contains("debian") {
            votes.push(("Linux", Some("Debian"), 70, format!("SSH banner: {banner}")));
        } else if lower.contains("openssh") {
            // OpenSSH version ranges can hint at OS
            votes.push(("Linux", None, 30, format!("OpenSSH (commonly Linux): {banner}")));
        }
    }

    // Port-based heuristics
    if open_ports.contains(&3389) {
        votes.push(("Windows", None, 40, "RDP port 3389 open".into()));
    }
    if open_ports.contains(&445) && !open_ports.contains(&22) {
        votes.push(("Windows", None, 35, "SMB port 445 open without SSH".into()));
    }
    if open_ports.contains(&22) && !open_ports.contains(&3389) {
        votes.push(("Linux", None, 20, "SSH port 22 open without RDP".into()));
    }

    if votes.is_empty() {
        return None;
    }

    // Tally votes per OS family
    let mut family_scores: std::collections::HashMap<&str, (u8, Option<&str>, Vec<String>)> =
        std::collections::HashMap::new();

    for (family, version, conf, evidence) in &votes {
        let entry = family_scores
            .entry(family)
            .or_insert((0, None, Vec::new()));
        entry.0 = entry.0.saturating_add(*conf);
        if version.is_some() {
            entry.1 = *version;
        }
        entry.2.push(evidence.clone());
    }

    // Pick the highest-scored family
    let (family, (score, version, evidence)) = family_scores
        .into_iter()
        .max_by_key(|(_, (s, _, _))| *s)?;

    // Cap at 95%
    let confidence = score.min(95);

    Some(OsGuess {
        os_family: family.to_string(),
        os_version: version.map(|v| v.to_string()),
        confidence,
        evidence,
    })
}
