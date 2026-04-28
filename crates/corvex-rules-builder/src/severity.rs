//! Severity normalisation across the three source tools.
//!
//! One source of truth. Each parser calls into here so every row that lands
//! in `rules.severity` came through the same mapping table.

use crate::normalized::{Confidence, Severity};

/// Map a Nikto `tuning` string (concatenated category chars) to severity.
///
/// Mirrors `severity_from_tuning` in
/// crates/corvex-plugins/src/tests_plugin.rs:31-49. Categories: 0=File Upload,
/// 1=Interesting Files, 2=Misconfig, 3=Info Disc, 4=XSS/Injection, 5=RFI,
/// 6=DoS, 7=RFR, 8=RCE, 9=SQLi, a=Auth Bypass, b=Software ID,
/// c=Remote Inclusion, d=WebService, e=Admin Console, f=XML Injection.
pub fn severity_from_nikto_tuning(tuning: &str) -> Severity {
    let mut best = Severity::Info;
    for c in tuning.chars() {
        let s = match c {
            '8' => Severity::Critical,
            '9' | '4' | 'f' => Severity::High,
            '0' | '5' | '6' | 'a' | 'c' => Severity::High,
            '2' | '7' | 'e' => Severity::Medium,
            '1' | '3' | 'd' => Severity::Low,
            'b' => Severity::Info,
            _ => Severity::Info,
        };
        if rank(s) > rank(best) {
            best = s;
        }
    }
    best
}

fn rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// ZAP's risk codes (`org.parosproxy.paros.core.scanner.Alert`) — 0..=3.
pub fn severity_from_zap_riskcode(code: i64) -> Severity {
    match code {
        3 => Severity::High,
        2 => Severity::Medium,
        1 => Severity::Low,
        0 => Severity::Info,
        _ => Severity::Info,
    }
}

/// ZAP's confidence codes (`Alert.CONFIDENCE_*`) — 0..=4.
/// 0=False positive, 1=Low, 2=Medium, 3=High, 4=Confirmed.
pub fn confidence_from_zap_code(code: i64) -> Option<Confidence> {
    match code {
        4 | 3 => Some(Confidence::High),
        2 => Some(Confidence::Medium),
        1 => Some(Confidence::Low),
        _ => None,
    }
}

/// BCheck severity literals: `info`, `low`, `medium`, `high`.
pub fn severity_from_burp_label(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// BCheck confidence literals: `firm`, `tentative`, `certain`.
pub fn confidence_from_burp_label(s: &str) -> Option<Confidence> {
    match s.trim().to_ascii_lowercase().as_str() {
        "certain" => Some(Confidence::High),
        "firm" => Some(Confidence::Medium),
        "tentative" => Some(Confidence::Low),
        _ => None,
    }
}
